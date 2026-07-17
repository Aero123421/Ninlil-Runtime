#!/usr/bin/env python3
"""Independent D3-S2 crossrow sibling oracle (append-only; stdlib only).

Appends D3-S2 suffix vectors onto the frozen D3-S1 94-vector prefix
produced by tools/domain_scan_crossrow_vector_gen.py:

  * 6 Mode21..26 empty-carrier / empty-secondary COMPLETE product smoke
  * Mode25 slice: CUM total=1 + RECENT C1 + true ANCHOR success, and
    RECENT-without-CUM carrier-ABSENT STORAGE_CORRUPT (note path)
  * Mode26 slice: EVENT_SPOOL resume=1 + MANAGEMENT RESUME + true ANCHOR
    stream success, and MANAGEMENT-without-EVENT_SPOOL carrier-ABSENT
    STORAGE_CORRUPT (note path)
  * Mode24 slice: RESULT_CACHE reply_count=1 + REVERSE_REPLY RECEIPT +
    true DELIVERY known-kind FOCUS/BIND success, and REVERSE_REPLY-
    without-RESULT_CACHE carrier-ABSENT STORAGE_CORRUPT (note path)
  * Mode23 slice: retained TRANSACTION_STATE + true ANCHOR + EVIDENCE
    slots 0..L (L=3) known-slot FOCUS/BIND success (nontrivial
    valid=M+overflow equation), and EVIDENCE-without-STATE BIND
    carrier-ABSENT STORAGE_CORRUPT (note path)
  * Mode22 slice: APPLICATION_FIRST RESULT_CACHE app=1 + DELIVERY-owned
    ATTEMPT stream + true DELIVERY BIND (INDEX ABSENT peer) success, and
    DELIVERY-owned ATTEMPT-without-RESULT_CACHE BIND carrier-ABSENT
    STORAGE_CORRUPT (note path)
  * Mode21 slice: live TRANSACTION_STATE cum=1 + TX-owned COMMAND ATTEMPT
    + matching ATTEMPT_ID_INDEX + true ANCHOR (FOCUS_ATTEMPT+FOCUS_INDEX
    stream + BIND pair both ways) COMPLETE success, and STATE+ANCHOR+
    ATTEMPT without INDEX peer under CLEANUP_PLAN PRESENT (cleanup_skip)
    BIND_ATTEMPT INDEX ABSENT STORAGE_CORRUPT (note path)
  * P0-A slice (§18.13.15 cases 2/6): Mode25 two-owner SHA256_COMPOSITE
    RETRY interleave (CUM+RECENT per owner; non-contiguous owner order)
    + two CUM carriers SELECT exactly once (no-skip/no-dup) COMPLETE
  * P0-B slice (§18.13.15 case 13 / §18.13.5 B5/B6/B11): Mode26 ES+MGMT
    mid-FOCUS stream budget stop then same-iterator resume (not B11 restart)
  * P0-C slice (§18.13.15 cases 7 remaining / 11): Mode25 BIND exact_get
    Port IO_ERROR → sticky STORAGE / FAILED; formal note_count=0 in JSON
    (reference model only; not a production call counter); production bridge
    proves Port fault + STORAGE outcome + exact trace (no fabricated CORRUPT).
    Two-txn list-then-count anti-pass: check + self-test port_trace tamper
    (production bridge enforces begin_calls==1 per vector)
  * P0-D slice (§18.13.15 cases 8 / 15): Mode22 DELIVERY-owned ATTEMPT with
    unexpected ATTEMPT_ID_INDEX PRESENT → BIND_ATTEMPT ABSENT-peer fail;
    Mode22 true-primary DELIVERY ABSENT; Mode21 primary PVD mismatch;
    Mode21 INDEX pair PRESENT subject/raw mismatch (constructible BIND pair
    subject residual after primary proven). True-primary raw after D1
    PRESENT+typed validate is identity-tautological/unconstructible under
    D1 same-record + same READ_ONLY snapshot — not claimed as coverage.
    Mode21 success BIND_INDEX no-STATE companion re-get pinned via existing
    d3_peer_get_count / exact Port-trace.
  * P1-A slice (§18.13.15 cases 4 / 14): ordinary CLEANUP_PLAN ABSENT stream
    count failures — Mode21 application ATTEMPT overcount; Mode21 cancel
    ATTEMPT overcount; Mode21 INDEX undercount (no CLEANUP skip); Mode22
    APPLICATION_FIRST empty-secondary undercount; Mode22 CANCEL_FIRST cancel
    undercount; Mode26 MANAGEMENT overcount. Independent formal + production
    bridge; not CLEANUP_PLAN skip as ordinary mismatch substitute.
  * P1-D slice (§18.13.15 case 12): Mode21 profile_mismatch and
    future_profile_candidate evaluator-off — baseline EXHAUSTED only (phase
    BASELINE + BASELINE_DONE; no COMPLETE/COMPLETE_READY authority); no
    INTERNAL reopen / BIND / peer get; finalize UNSUPPORTED/adopted0. Not
    recognizable_future_seen.
  * P1-D2 slice (§18.13.15 case 10): Mode21 count-green without BIND set —
    FOCUS ATTEMPT+INDEX count_complete_mask full, binding_complete_mask 0,
    phase BIND_ATTEMPT (BIND started, not COMPLETE), no sticky; call-level
    checkpoint freezes that exact shape; test-only false-terminal probe
    (session/context copy, copy.state=EXHAUSTED) must see finalize
    INVALID_STATE / Port0 / no cleanup / no output mutation; original
    session resumes BIND→COMPLETE/adopt1. Not missing-peer CORRUPT, not
    Port fault, not evaluator-off, not metadata-only.
  * P1-B1 slice (§18.13.15 case 5 / §18.13.8 Modes22–23 only): Mode22
    CLEANUP_PLAN PRESENT ordinary-skip positive — live RESULT_CACHE
    declares application_attempt_count>0, ATTEMPT secondary band empty,
    matching DELIVERY CLEANUP_PLAN PRESENT → cleanup_skip=1 so ordinary
    undercount is not noted; empty BIND_ATTEMPT completes → COMPLETE/
    adopt1; call-level checkpoint freezes cleanup_skip=1 after SELECT
    setup; Port-trace/get budget pin matching CLEANUP setup get. Mode23
    CLEANUP_PLAN PRESENT still-ordinary negative — matching TX
    CLEANUP_PLAN identity/typed row on same snapshot, Mode23 forces
    cleanup_skip=0, carrier STATE PRESENT + known-slot EVIDENCE slots
    insufficient → STORAGE_CORRUPT (real ordinary path; not false skip).
  * P1-B2 slice (§18.13.15 case 5 residual / §18.13.8 Modes24–26): three
    matching CLEANUP_PLAN PRESENT still-ordinary negatives (one formal
    vector each). Mode24: live RESULT_CACHE reply_count>0 + matching
    DELIVERY plan PRESENT + REVERSE_REPLY known-kind absent →
    cleanup_skip forced 0 → STORAGE_CORRUPT. Mode25: retained CUM
    total>0 + matching TX plan PRESENT + required RECENT slot absent →
    cleanup_skip=0 → STORAGE_CORRUPT. Mode26: live EVENT_SPOOL
    resume/discard declared>0 + matching TX plan PRESENT + MANAGEMENT
    secondary empty → cleanup_skip=0 stream undercount STORAGE_CORRUPT.
    Modes24–26 do not CLEANUP setup get; plan presence proven via same-
    snapshot matching typed row + baseline visit; Port-trace /
    d3_peer_get_count pin zero extra plan get. Checkpoints freeze
    cleanup_skip=0 / phase FAILED / FOCUS_LIVE. Case5 Mode21 existing +
    22/23 P1-B1 + 24–26 this slice aligned; does not claim D3-S2 complete.
  * P1-C1 slice (§18.13.15 cases 3/19 / §18.13.12.1 Mode23): illegal
    extra RAW slot L+1 BIND CORRUPT after FOCUS green; equation fail
    valid!=M+overflow FOCUS CORRUPT; late coherence observed_c>
    declared_c FOCUS CORRUPT (constructible under D1; no false late
    equality). Matching STATE+ANCHOR+required slots each vector.
  * P1-C2 slice (§18.13.15 case 3 residual / Modes24–25 known-slot
    legality): D1 already rejects reply_kind∉1..4, CUM slot≠0, RECENT
    slot>3 — those rows are NOT fabricated for S2 formal. Constructible
    substitutes are D1-valid carrier declared vs population shape fails:
    Mode24 reply_count vs closed-kind population under/over (missing RR
    or undeclared extra kind); Mode25 CUM total-derived recent_n vs
    D1-valid RECENT population under/over (missing or extra cycle/slot
    with correct body arithmetic). FOCUS known-slot/kind close notes
    STORAGE_CORRUPT; production already compare-fails (no false COMPLETE).

Does NOT invoke, import, link, or translate production C scanner/codec.
Does NOT claim full D3-S2 oracle complete (docs/17 §18.13.4 / .5 / .9 / .15).

Usage:
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py generate <path>
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py check <path>
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py emit-c-fixture <json> <header>
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py self-test
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
D3S1_GEN_PATH = REPO_ROOT / "tools" / "domain_scan_crossrow_vector_gen.py"
DEFAULT_JSON = REPO_ROOT / "spec" / "vectors" / "domain-scan-crossrow-v1.json"

FORMAT = "ninlil-domain-scan-crossrow-v1-d3s2"
VERSION = 1
D3S1_PREFIX_COUNT = 94
D3S2_SMOKE_COUNT = 6
D3S2_MODE25_SLICE_COUNT = 2
D3S2_MODE26_SLICE_COUNT = 2
D3S2_MODE24_SLICE_COUNT = 2
D3S2_MODE23_SLICE_COUNT = 2
D3S2_MODE22_SLICE_COUNT = 2
D3S2_MODE21_SLICE_COUNT = 2
D3S2_P0A_SLICE_COUNT = 1
D3S2_P0B_SLICE_COUNT = 1
D3S2_P0C_SLICE_COUNT = 1
D3S2_P0D_SLICE_COUNT = 4
D3S2_P1A_SLICE_COUNT = 6
D3S2_P1D_SLICE_COUNT = 2
D3S2_P1D2_SLICE_COUNT = 1
D3S2_P1B1_SLICE_COUNT = 2
D3S2_P1B2_SLICE_COUNT = 3
D3S2_P1C1_SLICE_COUNT = 6
D3S2_P1C2_SLICE_COUNT = 4
D3S2_SUFFIX_COUNT = (
    D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
    + D3S2_P1D_SLICE_COUNT
    + D3S2_P1D2_SLICE_COUNT
    + D3S2_P1B1_SLICE_COUNT
    + D3S2_P1B2_SLICE_COUNT
    + D3S2_P1C1_SLICE_COUNT
    + D3S2_P1C2_SLICE_COUNT
)  # 49
EXPECTED_VECTOR_COUNT = D3S1_PREFIX_COUNT + D3S2_SUFFIX_COUNT  # 143
D3S2_100_PREFIX_COUNT = D3S1_PREFIX_COUNT + D3S2_SMOKE_COUNT  # 100
D3S2_102_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT + D3S2_SMOKE_COUNT + D3S2_MODE25_SLICE_COUNT
)  # 102
D3S2_104_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
)  # 104
D3S2_106_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
)  # 106
D3S2_108_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
)  # 108
D3S2_110_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
)  # 110
D3S2_112_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
)  # 112 (prior freeze before P0-A)
D3S2_113_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
)  # 113 (origin/main freeze before P0-B)
D3S2_114_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
)  # 114 (origin/main freeze before P0-C)
D3S2_115_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
)  # 115 (origin/main freeze before P0-D)
CEILING = 8192

# Frozen D3-S1 prefix identity (byte-for-byte rebuild pin).
D3S1_FORMAT = "ninlil-domain-scan-crossrow-v1-d3s1"
D3S1_PREFIX_CONTENT_SHA256 = (
    "76b28d847be8cd7a95e8f1879400403abf702931a3de170a473c7c0f76d95468"
)
D3S1_PREFIX_FINGERPRINT_HASH = (
    "2c99af3c9b3aea228e4478c0d2739352f111fdd8c42303bf07177f8bb8ee8c58"
)

# Frozen 100-vector append-only prefix (94 D3S1 + 6 D3S2 smoke) — prior main.
D3S2_100_CONTENT_SHA256 = (
    "880e4b62cf62eb667397b9c58e547298290df92c87a4308400274e9db090fc89"
)
D3S2_100_FINGERPRINT_HASH = (
    "0d769bba784c0f2250f27d382d4150c22570095da6f12b237b9e49d2bd6c9a0c"
)

# Frozen 102-vector append-only prefix (100 + Mode25 slice).
D3S2_102_CONTENT_SHA256 = (
    "31bee901f9ab613cf7fe1d8e58b28a1c28ea174e8869a859d0a6c756c2ec88ea"
)
D3S2_102_FINGERPRINT_HASH = (
    "c399e6d7a39de7792c7782ee70468f5508d984df509ed3a2b602baa8fb39e246"
)

# Frozen 104-vector append-only prefix (102 + Mode26 slice).
D3S2_104_CONTENT_SHA256 = (
    "03915c54e1e1bbfce20392d36428f5e50c03c91d016c24ec0aba0fb9d0c2f629"
)
D3S2_104_FINGERPRINT_HASH = (
    "baac26572c63a72c3ae90cc02f56b89017100a046aebedeed734ee3fa0ed1b22"
)

# Frozen 106-vector append-only prefix (104 + Mode24 slice) — prior main.
D3S2_106_CONTENT_SHA256 = (
    "3c5f7bfaea92ffa7a4373a48cddfb36936fac23332dfc6fe7c69e0cf5f7b88c2"
)
D3S2_106_FINGERPRINT_HASH = (
    "dba8c377074892b934cd4417ce5a0d1bd917f93b3fa2b49ba023873b15467a1f"
)

# Frozen 108-vector append-only prefix (106 + Mode23 slice) — prior main.
# content hash + fingerprint chain independently derived from origin/main
# 108-vector artifact (not recomputed by rewriting published objects).
D3S2_108_CONTENT_SHA256 = (
    "23e504f1346c04d9a9ee6b59a5eae9bca3b52e4a4de2460c61d0ce7043efab66"
)
D3S2_108_FINGERPRINT_HASH = (
    "724d58e23d504f65b12ab0a6dc7e4df51cfd18c1cc3be956cd4aed560a67a25a"
)

# Frozen 110-vector append-only prefix (108 + Mode22 slice) — prior main.
# content hash + fingerprint chain independently derived from origin/main
# 110-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_110_CONTENT_SHA256 = (
    "344f28319a7bc1cf4d1265f35e37ff3360a59d36b1799d0774b5fa7a6780c026"
)
D3S2_110_FINGERPRINT_HASH = (
    "8cb323608764c52243e75b5978a3e4c7bea904ba846bc72472c6f5f61a165c39"
)

# Frozen 112-vector append-only prefix (110 + Mode21 slice) — prior main.
# content hash + fingerprint chain independently derived from that release
# (full document content_sha256 / prior_fingerprint chain; not recomputed
# by rewriting published objects).
D3S2_112_CONTENT_SHA256 = (
    "519bc7465b47bc6da957e8815c112da6445a811c5fcb5b65ff9c3cd3038bff79"
)
D3S2_112_FINGERPRINT_HASH = (
    "0a3653d5b03ad5f22be66bfb24149fe8ed434f1345d391bfb5a3d1ac39c42968"
)

# Frozen 113-vector append-only prefix (112 + P0-A) — origin/main.
# content hash + fingerprint chain independently derived from origin/main
# 113-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_113_CONTENT_SHA256 = (
    "e47daa2aa251f36b8ad1d3d9621e6f41ebe0066b2420f8a9e87c3481f14566b7"
)
D3S2_113_FINGERPRINT_HASH = (
    "d3f044ede266118ec9237ae3e01b539ff5c5fdfd85aaec3b7a31791f3c326057"
)

# Frozen 114-vector append-only prefix (113 + P0-B) — origin/main.
# content hash + fingerprint chain independently derived from origin/main
# 114-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_114_CONTENT_SHA256 = (
    "e1c1cd329f2ce817a49a461d2b86af25adda30573b4af83d3ba6d24cc00c49fe"
)
D3S2_114_FINGERPRINT_HASH = (
    "caadacfe3a26a86c71661d656908d65eec3133355db9ab7fb4d5df6f0b388fd7"
)
# Frozen 115-vector append-only prefix (114 + P0-C) — origin/main.
# content hash + fingerprint chain independently derived from origin/main
# 115-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_115_CONTENT_SHA256 = (
    "605a77d256e5bcadddba5a5973ab2d59d86687d5988a5e686d6e4a093dcd8059"
)
D3S2_115_FINGERPRINT_HASH = (
    "0d272c1a7d25f4dc0c299964872870e77e1ba5de8a4844da7fe8d584928623fa"
)
# Frozen 119-vector append-only prefix (115 + P0-D) — origin/main before P1-A.
# content hash + fingerprint chain independently derived from origin/main
# 119-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_119_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
)  # 119 (origin/main freeze before P1-A)
D3S2_119_CONTENT_SHA256 = (
    "63ed46d9ba467e95ed53781f096d581fa42234e0e41cbb7022ffb1df23eeeb40"
)
D3S2_119_FINGERPRINT_HASH = (
    "7be397142432bedc2784ebd87fba4ef590b6b1a0129ba6e2d6e81b87a50ab9d7"
)
# Frozen 125-vector append-only prefix (119 + P1-A) — origin/main before P1-D.
# content hash + fingerprint chain independently derived from origin/main
# 125-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_125_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
)  # 125 (origin/main freeze before P1-D)
D3S2_125_CONTENT_SHA256 = (
    "6043e624047f1036efd1b1a2936eadefc9123b8661e454077320bfb22ceebb00"
)
D3S2_125_FINGERPRINT_HASH = (
    "e0bd3628dc5a2f85bb0b1abca7499008b82861ecc2047000fc124be6075293f0"
)
# Frozen 127-vector append-only prefix (125 + P1-D) — origin/main before P1-D2.
# content hash + fingerprint chain independently derived from origin/main
# 127-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_127_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
    + D3S2_P1D_SLICE_COUNT
)  # 127 (origin/main freeze before P1-D2)
D3S2_127_CONTENT_SHA256 = (
    "58deba31f6378872493117f0cd644d655fdb5ed6d4d5ca50cb6d387c70b21001"
)
D3S2_127_FINGERPRINT_HASH = (
    "1215ad1e34a9c11e81e122bb980233a2b9898b73e6c5f6f3994af01106b028c4"
)
# Frozen 128-vector append-only prefix (127 + P1-D2) — origin/main before P1-B1.
# content hash + fingerprint chain independently derived from origin/main
# 128-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_128_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
    + D3S2_P1D_SLICE_COUNT
    + D3S2_P1D2_SLICE_COUNT
)  # 128 (origin/main freeze before P1-B1)
D3S2_128_CONTENT_SHA256 = (
    "1d3496bd184aa197e5a7a9f73f27a8de9edce8809f1eef6f60055f81037dbd12"
)
D3S2_128_FINGERPRINT_HASH = (
    "d82f7677180fd28a866f9b763ebbb6ea52a269afe273f85e18e686460be15e66"
)
# Frozen 130-vector append-only prefix (128 + P1-B1) — origin/main before P1-B2.
# content hash + fingerprint chain independently derived from origin/main
# 130-vector artifact (full document content_sha256 / prior_fingerprint
# chain of that release; not recomputed by rewriting published objects).
D3S2_130_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
    + D3S2_P1D_SLICE_COUNT
    + D3S2_P1D2_SLICE_COUNT
    + D3S2_P1B1_SLICE_COUNT
)  # 130 (origin/main freeze before P1-B2)
D3S2_130_CONTENT_SHA256 = (
    "eb2e32b452632e2f3ac08e7376262eb537498745f9c6dce5ccae4abcf3b4f2e6"
)
D3S2_130_FINGERPRINT_HASH = (
    "7eaaa8e30709cdcbccbc81cf2a5a8f5461aef2c74e315f1b0a08864d7fab2cbf"
)
# Frozen 133-vector append-only prefix (130 + P1-B2) — origin/main before P1-C1.
# content hash + fingerprint chain from origin/main 133-vector artifact
# (PR#69 / self-test-perf main; full-object prefix absolute invariant).
D3S2_133_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
    + D3S2_P1D_SLICE_COUNT
    + D3S2_P1D2_SLICE_COUNT
    + D3S2_P1B1_SLICE_COUNT
    + D3S2_P1B2_SLICE_COUNT
)  # 133 (origin/main freeze before P1-C1)
D3S2_133_CONTENT_SHA256 = (
    "65f58bfe71d71ccbb3bb553223f6762a14c022c110be481e061475cf3a84c98d"
)
D3S2_133_FINGERPRINT_HASH = (
    "031fdef1204ef7ca56d6c9fdca56d750a4d3d4bc3c4cdf433023ddbc508cd871"
)
# Frozen 139-vector append-only prefix (133 + P1-C1) — origin/main before P1-C2.
# content hash + fingerprint chain from origin/main 139-vector artifact
# (PR#70 Mode23 evidence coherence; full-object prefix absolute invariant).
D3S2_139_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
    + D3S2_MODE21_SLICE_COUNT
    + D3S2_P0A_SLICE_COUNT
    + D3S2_P0B_SLICE_COUNT
    + D3S2_P0C_SLICE_COUNT
    + D3S2_P0D_SLICE_COUNT
    + D3S2_P1A_SLICE_COUNT
    + D3S2_P1D_SLICE_COUNT
    + D3S2_P1D2_SLICE_COUNT
    + D3S2_P1B1_SLICE_COUNT
    + D3S2_P1B2_SLICE_COUNT
    + D3S2_P1C1_SLICE_COUNT
)  # 139 (origin/main freeze before P1-C2)
D3S2_139_CONTENT_SHA256 = (
    "c6e2bfe29e4e319f84133fa60faf180c6db5221d37c854cdd3c0132d520b0f3d"
)
D3S2_139_FINGERPRINT_HASH = (
    "456a446a069fb65fed01f81b9ba9556d12a6bbe9796c7e7ed2317a707416e5be"
)


# D1 authority pins for Mode25 material (independent of production C).
D1_CUM_ID = "DSB3_RS_CUM_T0_TYPED"
D1_REC_ID = "DSB3_RS_REC_C1_TYPED"
D1_ANCHOR_ID = "DSB2_ANCHOR_TYPED"
# P0-A Mode25 multi-owner: bounded deterministic TX pair pin.
# Search space = last-byte pairs on D1 base prefix 71||00*14 with TX_A fixed
# to D1 default (...99). First ascending last-byte B yielding complete-key
# owner order ABAB among (CUM,REC)×2 is B_last=0x0c. Self-tested.
MODE25_MULTI_TX_A = bytes.fromhex(
    "71000000000000000000000000000099"
)
MODE25_MULTI_TX_B = bytes.fromhex(
    "7100000000000000000000000000000c"
)
MODE25_MULTI_OWNER_ORDER_PIN = "ABAB"
MODE25_MULTI_KIND_ORDER_PIN = (1, 1, 2, 2)  # CUM,CUM,REC,REC
RS_KIND_CUMULATIVE = 1
RS_KIND_RECENT = 2

# D1 authority pins for Mode26 material (independent of production C).
D1_ES_ID = "DSB3_ES_ACTIVE_TYPED"
D1_ML_ID = "DSB3_ML_R_RSN1_TYPED"
# EVENT_SPOOL body: successful_resume_count u32 BE at body offset 260;
# discard_committed u32 BE at 264 (docs/17 §8.6 D1-B3k; independent parse).
ES_RESUME_BODY_OFF = 260
ES_DISCARD_BODY_OFF = 264
ML_KIND_RESUME = 15
ML_TX_BODY_OFF = 28  # after operation_id[16] + kind u16 + reserved u16 + seq u64

# D1 authority pins for Mode24 material (independent of production C).
D1_DLV_ID = "DSB3_DLV_APP_DS_TYPED"
D1_RC_ID = "DSB3_RC_RESULT_POS_TYPED"
D1_RR_ID = "DSB3_RR_KIND_RECEIPT_TYPED"
# RESULT_CACHE body (exact 378): reply_count u32 BE after
# delivery_raw:RAW16(82) + delivery_kd[32] + txn[16] + n:u64 + app_seen:u32
# + app_attempt:u32 + state:u32 → body offset 150 (docs/17 §8.5 D1-B3i).
RC_REPLY_COUNT_BODY_OFF = 150
# REVERSE_REPLY body (exact 330): reply_key_raw:RAW16(86) where contents =
# delivery_key_raw:RAW16(82) || reply_kind:u32; closed kinds 1..4
# (RECEIPT..CANCEL_RESULT). Kind wire lives at body offset 2+82.
RR_REPLY_KIND_BODY_OFF = 84  # 2 (RAW16 len) + 82 (delivery RAW16 prefix)
RR_KIND_RECEIPT = 1
RR_KIND_DISPOSITION = 2
RR_KIND_MIN = 1
RR_KIND_MAX = 4
# Body field reply_kind after reply_key:RAW16(88) + delivery:RAW16(82) + txn16.
RR_BODY_REPLY_KIND_FIELD_OFF = 186  # 2+86 + 2+80 + 16
DLV_KEY_CONTENTS_BYTES = 80

# D1 authority pins for Mode22 material (independent of production C).
# RESULT_CACHE / DELIVERY share Mode24 authority IDs; ATTEMPT is DLV-owned.
D1_ATT_DLV_ID = "DSB3_ATT_DLV_CMD_REMOTE_TYPED"
# RESULT_CACHE body (exact 378): application_attempt_count u32 BE at body
# offset 142 (after delivery_raw:RAW16(82) + kd[32] + txn[16] + n:u64
# + app_seen:u32); reply_count remains at 150 (docs/17 §8.5 D1-B3i).
RC_APP_ATTEMPT_BODY_OFF = 142
# ATTEMPT body length depends on owner raw: DELIVERY raw80 → exact 322;
# TRANSACTION raw16 → exact 258 (docs/17 §8.3 D1-B3d).
ATT_BODY_LEN = 322
ATT_TX_BODY_LEN = 258
ATT_OWNER_KIND_TRANSACTION = 1
ATT_OWNER_KIND_DELIVERY = 2
ATT_KIND_COMMAND = 1
ATT_KIND_CANCEL = 3
# TRANSACTION_STATE body exact 224: cumulative_attempts u64 BE at body
# offset 84 (after txn16 + anchor_pvd32 + 6×u32 + retry_cycle u64 +
# attempt_in_cycle u32) — docs/17 §8.2 D1-B3c; independent of production C.
STATE_BODY_LEN = 224
STATE_CUM_ATTEMPTS_BODY_OFF = 84
# ATTEMPT_ID_INDEX body exact 100: attempt_id[16] + txn[16] + kind u16 +
# reserved u16 + attempt_record_key_digest[32] + creation_value_digest[32].
AII_BODY_LEN = 100
AII_ATTEMPT_RECORD_KEY_DIGEST_OFF = 36
# Mode21 pair-absent constructible path uses CLEANUP_PLAN PRESENT so
# ordinary A/B/C undercount is skipped (cleanup_skip) and BIND_ATTEMPT
# INDEX peer ABSENT is reachable (matches unit test + §18.13.5).
D1_ATT_TX_ID = "DSB3_ATT_TX_CMD_PREP_TYPED"
D1_ATT_TX_CAN_ID = "DSB3_ATT_TX_CAN_PREP_TYPED"
D1_AII_ID = "DSB3_AII_CMD_TYPED"
D1_CP_TX_ID = "DSB3_CP_TX_P1_FULL_TYPED"
D1_CP_DLV_ID = "DSB3_CP_DLV_P1_TYPED"
D1_RC_CANCEL_FIRST_ID = "DSB3_RC_CANCEL_FIRST_TYPED"
D1_CS_DLV_TOO_LATE_ID = "DSB3_CS_DLV_TOO_LATE_TYPED"

# D1 authority pins for Mode23 material (independent of production C).
D1_STATE_ID = "DSB2_STATE_TYPED"
D1_EV_SUM_MAT_ID = "DSB3_EV_TX_SUM_MAT_LEN0_TYPED"
D1_EV_SUM_EMPTY_ID = "DSB3_EV_TX_SUM_EMPTY_TYPED"
D1_EV_RAW_UNUSED_ID = "DSB3_EV_TX_RAW_UNUSED_TYPED"
D1_EV_RAW_MAT_ID = "DSB3_EV_TX_RAW_MAT_TYPED"
D1_EV_DLV_SUM_EMPTY_ID = "DSB3_EV_DLV_SUM_EMPTY_TYPED"
D1_DLV_APP_DS_ID = "DSB3_DLV_APP_DS_TYPED"
# EVIDENCE_CELL TX body exact 734 (docs/17 §8.3 D1-B3g): owner TX raw16=16.
# Offsets after owner_kind:u16 + cell_kind:u16 + RAW16(18) + pkd32 + target32.
EV_TX_BODY_LEN = 734
EV_CELL_KIND_BODY_OFF = 2
EV_OWNER_RAW_LEN = 16
EV_SLOT_BODY_OFF = 86  # 2+2+2+16+32+32
EV_CELL_STATE_BODY_OFF = 90
EV_LATE_MATERIAL_BODY_OFF = 114  # after reserved0 + 5*u32 stages/disp/effect
EV_VALID_BODY_OFF = 702  # last four u64 counters
EV_OVERFLOW_BODY_OFF = 718
EV_LATE_COUNT_BODY_OFF = 726
EV_OWNER_KIND_TX = 1
EV_CELL_KIND_SUMMARY = 1
EV_CELL_KIND_RAW = 2
EV_CELL_STATE_UNUSED = 1
EV_CELL_STATE_MATERIALIZED = 2
# Accepted profile default_binding max_evidence_per_target (not a cell field).
MODE23_ACCEPTED_L = 3

# Phase / mask constants (docs/17 §18.13; match domain_store_d3s2.h).
PHASE_BASELINE = 1
PHASE_FOCUS_ATTEMPT = 3
PHASE_FOCUS_EVIDENCE = 5
PHASE_FOCUS_REPLY = 6
PHASE_FOCUS_RETRY = 7
PHASE_FOCUS_MANAGEMENT = 8
PHASE_BIND_ATTEMPT = 9
PHASE_COMPLETE = 15
PHASE_FAILED = 16
PASS_BASELINE = 0
PASS_INTERNAL = 1
FLAG_BASELINE_DONE = 0x01
FLAG_FOCUS_LIVE = 0x02
FLAG_BIND_PHASE_ACTIVE = 0x04
FLAG_COMPLETE_READY = 0x08
MASK_ATTEMPT = 0x01
MASK_INDEX = 0x02
MASK_EVIDENCE = 0x04
MASK_REPLY = 0x08
MASK_RETRY = 0x10
MASK_MANAGEMENT = 0x20

MODE_BIND_MASK = {
    21: MASK_ATTEMPT | MASK_INDEX,
    22: MASK_ATTEMPT,
    23: MASK_EVIDENCE,
    24: MASK_REPLY,
    25: MASK_RETRY,
    26: MASK_MANAGEMENT,
}
# Empty-carrier smoke drive chunks (Mode21 BIND has two subtypes).
MODE_DRIVE_COUNT = {21: 4, 22: 3, 23: 3, 24: 3, 25: 3, 26: 3}
MODE_ITER_OPEN = {21: 4, 22: 3, 23: 3, 24: 3, 25: 3, 26: 3}

D3S2_SMOKE_KINDS = frozenset(
    {
        "mode21_empty_carrier_empty_secondary_ok",
        "mode22_empty_carrier_empty_secondary_ok",
        "mode23_empty_carrier_empty_secondary_ok",
        "mode24_empty_carrier_empty_secondary_ok",
        "mode25_empty_carrier_empty_secondary_ok",
        "mode26_empty_carrier_empty_secondary_ok",
    }
)
D3S2_MODE25_KINDS = frozenset(
    {
        "mode25_cum_total1_recent_slot1_anchor_ok",
        "mode25_recent_without_cum_carrier_absent_corrupt",
    }
)
D3S2_MODE26_KINDS = frozenset(
    {
        "mode26_es_resume1_mgmt_resume_anchor_ok",
        "mode26_mgmt_without_es_carrier_absent_corrupt",
    }
)
D3S2_MODE24_KINDS = frozenset(
    {
        "mode24_rc_reply1_receipt_delivery_ok",
        "mode24_rr_without_rc_carrier_absent_corrupt",
    }
)
D3S2_MODE23_KINDS = frozenset(
    {
        "mode23_tx_state_slots_L_equation_anchor_ok",
        "mode23_evidence_without_state_carrier_absent_corrupt",
    }
)
D3S2_MODE22_KINDS = frozenset(
    {
        "mode22_rc_app1_dlv_attempt_delivery_ok",
        "mode22_att_without_rc_carrier_absent_corrupt",
    }
)
D3S2_MODE21_KINDS = frozenset(
    {
        "mode21_state_cum1_att_tx_aii_anchor_ok",
        "mode21_att_without_aii_index_pair_absent_corrupt",
    }
)
D3S2_P0A_KINDS = frozenset(
    {
        "mode25_two_owner_sha_interleave_dual_carrier_ok",
    }
)
D3S2_P0B_KINDS = frozenset(
    {
        "mode26_es_mgmt_budget_mid_focus_resume_ok",
    }
)
D3S2_P0C_KINDS = frozenset(
    {
        "mode25_bind_exact_get_port_failure_note0",
    }
)
D3S2_P0D_KINDS = frozenset(
    {
        "mode22_att_unexpected_aii_index_present_corrupt",
        "mode22_att_true_primary_delivery_absent_corrupt",
        "mode21_att_primary_pvd_mismatch_corrupt",
        "mode21_att_index_pair_subject_raw_mismatch_corrupt",
    }
)
D3S2_P1A_KINDS = frozenset(
    {
        "mode21_app_attempt_stream_overcount_corrupt",
        "mode21_cancel_attempt_stream_overcount_corrupt",
        "mode21_index_stream_undercount_corrupt",
        "mode22_app_first_empty_secondary_undercount_corrupt",
        "mode22_cancel_first_cancel_undercount_corrupt",
        "mode26_mgmt_stream_overcount_corrupt",
    }
)
D3S2_P1D_KINDS = frozenset(
    {
        "mode21_profile_mismatch_evaluator_off_unsupported",
        "mode21_future_profile_evaluator_off_unsupported",
    }
)
D3S2_P1D2_KINDS = frozenset(
    {
        "mode21_count_green_bind_incomplete_false_terminal_ok",
    }
)
D3S2_P1B1_KINDS = frozenset(
    {
        "mode22_cleanup_plan_present_ordinary_skip_ok",
        "mode23_cleanup_plan_present_still_ordinary_corrupt",
    }
)
D3S2_P1B2_KINDS = frozenset(
    {
        "mode24_cleanup_plan_present_still_ordinary_corrupt",
        "mode25_cleanup_plan_present_still_ordinary_corrupt",
        "mode26_cleanup_plan_present_still_ordinary_corrupt",
    }
)
D3S2_P1C1_KINDS = frozenset(
    {
        "mode23_illegal_slot_L_plus_1_bind_corrupt",
        "mode23_equation_fail_valid_ne_m_plus_overflow_corrupt",
        "mode23_late_coherence_observed_gt_declared_corrupt",
        "mode23_cancel_first_slot0_bind_corrupt",
        "mode23_multi_owner_cancel_last_tx_ok",
        "mode23_multi_owner_tx_before_cancel_ev_corrupt",
    }
)
D3S2_P1C2_KINDS = frozenset(
    {
        "mode24_rc_reply1_empty_secondary_undercount_corrupt",
        "mode24_rc_reply1_extra_disposition_overcount_corrupt",
        "mode25_cum_total1_recent_missing_undercount_corrupt",
        "mode25_cum_total1_recent_extra_slot_overcount_corrupt",
    }
)
D3S2_REQUIRED_KINDS = (
    D3S2_SMOKE_KINDS
    | D3S2_MODE25_KINDS
    | D3S2_MODE26_KINDS
    | D3S2_MODE24_KINDS
    | D3S2_MODE23_KINDS
    | D3S2_MODE22_KINDS
    | D3S2_MODE21_KINDS
    | D3S2_P0A_KINDS
    | D3S2_P0B_KINDS
    | D3S2_P0C_KINDS
    | D3S2_P0D_KINDS
    | D3S2_P1A_KINDS
    | D3S2_P1D_KINDS
    | D3S2_P1D2_KINDS
    | D3S2_P1B1_KINDS
    | D3S2_P1B2_KINDS
    | D3S2_P1C1_KINDS
    | D3S2_P1C2_KINDS
)

SCANNER_CALL_OPS = frozenset(
    {
        "begin_profiled",
        "begin_profiled_d3s1",
        "begin_profiled_d3s2",
        "d3s2_drive",
        "advance",
        "exact_get",
        "note_terminal_corrupt",
        "finalize",
        "abort",
    }
)
# Test-bridge-only call ops (not production public API; expected_status real).
TEST_BRIDGE_CALL_OPS = frozenset({"probe_false_terminal_finalize"})
HARNESS_CALL_OPS = frozenset({"session_init", "use_rows", "handle_drift"})
CLOSED_CALL_OPS = SCANNER_CALL_OPS | HARNESS_CALL_OPS | TEST_BRIDGE_CALL_OPS
FORBIDDEN_CALL_OPS = frozenset({"begin", "begin_transport", "transport_begin"})

VECTOR_KEYS = frozenset(
    {
        "id",
        "kind",
        "mode",
        "candidate_binding",
        "rows",
        "alt_rows",
        "faults",
        "calls",
        "expected",
        "d1_refs",
        "source_ref",
        "peer_ref",
        "row_refs",
        "notes",
        "ownership",
    }
)

# D3-S1 expected keys (prefix must match exactly).
D3S1_EXPECTED_KEYS = frozenset(
    {
        "final_status",
        "adopted",
        "state_after",
        "recognizable_future_seen",
        "family14_row_count",
        "current_domain_key_count",
        "ok_row_count",
        "profile_exact_active",
        "profile_mismatch",
        "future_profile_candidate",
        "profile_get_present_mask",
        "family14_iter_seen_mask",
        "reopen_required",
        "close_count",
        "mutation_calls",
        "iter_open_count",
        "port_trace",
        "has_sticky_primary",
        "sticky_primary",
        "d3_peer_get_count",
        "d3_mode_applicable_count",
    }
)
D3S2_EXPECTED_EXTRA = frozenset(
    {
        "phase",
        "count_complete_mask",
        "binding_complete_mask",
        "flags",
    }
)
D3S2_EXPECTED_KEYS = D3S1_EXPECTED_KEYS | D3S2_EXPECTED_EXTRA
# Optional formal field only on new vectors (P0-C+). Existing suffix objects
# omit it. Independent reference-model expectation (generator check/self-test);
# not a production note_terminal_corrupt call counter and not emitted to the
# production bridge C fixture.
D3S2_EXPECTED_OPTIONAL_KEYS = frozenset({"note_count"})

CALL_KEYS = frozenset(
    {
        "op",
        "row_budget",
        "key_hex",
        "name",
        "expected_status",
        "mode",
        "context",
        # Optional call-level production context/spy checkpoint (P0-B).
        # Absent or has_checkpoint=0 ⇒ no post-call context compare.
        "has_checkpoint",
        "cp_phase",
        "cp_focus_live",
        "cp_observed_a",
        "cp_observed_b",
        "cp_observed_c",
        "cp_count_complete_mask",
        "cp_binding_complete_mask",
        "cp_flags",
        "cp_pass_kind",
        "cp_cleanup_skip",
        "cp_last_carrier_key_len",
        "cp_last_carrier_key_hex",
        "cp_begin_calls",
        "cp_iter_open_calls",
        "cp_iter_close_calls",
        "cp_trace_count",
    }
)

# Required scalar fields when has_checkpoint == 1 (closed; no name-string abuse).
CHECKPOINT_REQUIRED_KEYS = frozenset(
    {
        "has_checkpoint",
        "cp_phase",
        "cp_focus_live",
        "cp_observed_a",
        "cp_observed_b",
        "cp_observed_c",
        "cp_count_complete_mask",
        "cp_binding_complete_mask",
        "cp_flags",
        "cp_pass_kind",
        "cp_cleanup_skip",
        "cp_last_carrier_key_len",
        "cp_begin_calls",
        "cp_iter_open_calls",
        "cp_iter_close_calls",
        "cp_trace_count",
    }
)

SCOPE = (
    "D3-S2 crossrow sibling oracle (append-only on domain-scan-crossrow-v1): "
    "frozen 94-vector D3-S1 exact-1 prefix retained byte-for-byte; frozen "
    "100-vector pin (94 + 6 Mode21..26 empty-carrier smoke) retained; frozen "
    "102-vector pin (100 + Mode25 slice) retained; frozen 104-vector pin "
    "(102 + Mode26 slice) retained; frozen 106-vector pin (104 + Mode24 "
    "slice) retained; frozen 108-vector pin (106 + Mode23 slice) retained; "
    "frozen 110-vector pin (108 + Mode22 slice) retained as append-only "
    "prefix; Mode21 slice appends live TRANSACTION_STATE "
    "(cumulative_attempts=1, cancel=0) carrier + TX-owned COMMAND ATTEMPT "
    "+ matching ATTEMPT_ID_INDEX + true ANCHOR: FOCUS_ATTEMPT+FOCUS_INDEX "
    "stream (observed A=1/B=0/C=1; true iterator EXHAUSTED count bit0|bit1) "
    "+ BIND_ATTEMPT (STATE carrier + ANCHOR PVD/raw + INDEX PRESENT pair) "
    "+ BIND_INDEX (ANCHOR + ATTEMPT PRESENT pair; no STATE re-get) COMPLETE "
    "success, and STATE+ANCHOR+ATTEMPT without INDEX under CLEANUP_PLAN "
    "PRESENT (cleanup_skip so ordinary INDEX undercount does not preempt "
    "BIND) BIND_ATTEMPT INDEX peer ABSENT STORAGE_CORRUPT (note path; "
    "primary already proven before pair; BIND_INDEX must not run). Each "
    "vector is one mode per independent READ_ONLY txn; baseline once + "
    "sequential zero-prefix reopen; stream FOCUS closes only on true "
    "iterator EXHAUSTED; SHA256_COMPOSITE ATTEMPT rows complete-key lex "
    "sorted; mutation_calls=0. Frozen 113-vector origin/main pin retained "
    "(112 + P0-A multi-owner Mode25). P0-B appends Mode26 EVENT_SPOOL "
    "resume=1 + MANAGEMENT RESUME mid-FOCUS stream budget stop (B5): "
    "FOCUS_MANAGEMENT row_budget derived from fixture OK-row count so the "
    "last MANAGEMENT OK is observed then advance stops before NOT_FOUND; "
    "call-level checkpoint freezes phase/focus_live/observed/masks/flags/"
    "pass_kind/cleanup_skip/last_carrier_key_len + spy begin/iter_open/"
    "iter_close/trace_count; next drive resumes same iterator (B6 close; "
    "not B11 restart); final SELECT empty→BIND→COMPLETE matches one-shot "
    "Mode26 success semantics. Frozen 114-vector origin/main pin retained "
    "(113 + P0-B). P0-C appends Mode25 BIND exact_get Port IO_ERROR mid-"
    "BIND (after FOCUS known-slot matrix): sticky NINLIL_E_STORAGE / phase "
    "FAILED; formal JSON note_count=0 is reference-model only (not a "
    "production note_terminal_corrupt call counter); production bridge proves "
    "Port fault + STORAGE sticky/FAILED + incomplete BIND + exact trace. "
    "Fault is real spy get on_call after baseline 17 + FOCUS 5 peer gets. "
    "Frozen 115-vector origin/main pin retained (114 + P0-C). P0-D appends "
    "Mode22 unexpected ATTEMPT_ID_INDEX PRESENT (BIND_ATTEMPT ABSENT-peer "
    "fail after carrier+primary proven), Mode22 true-primary DELIVERY "
    "ABSENT (carrier RC proven first), Mode21 primary PVD mismatch, and "
    "Mode21 INDEX pair PRESENT subject/raw mismatch under CLEANUP_PLAN "
    "(constructible BIND pair subject residual after primary proven). "
    "True-primary raw after PRESENT+typed validate remains identity-"
    "tautological/unconstructible under D1 same-record + same READ_ONLY "
    "snapshot and is not claimed as P0-D coverage. Mode21 success "
    "BIND_INDEX no-STATE companion re-get remains pinned by "
    "d3_peer_get_count=7 and exact Port-trace (BIND_INDEX segment exact "
    "2 gets). "
    "Frozen 119-vector origin/main pin retained (115 + P0-D). P1-A appends "
    "ordinary CLEANUP_PLAN ABSENT stream count failures: Mode21 app "
    "ATTEMPT overcount (declared A=0 observed A=1 at FOCUS_ATTEMPT H2), "
    "Mode21 cancel ATTEMPT overcount (declared B=0 observed B=1), Mode21 "
    "INDEX undercount (FOCUS_ATTEMPT green then FOCUS_INDEX C 0!=1; no "
    "CLEANUP skip), Mode22 APPLICATION_FIRST carrier PRESENT declared A=1 "
    "empty ATTEMPT band undercount, Mode22 CANCEL_FIRST cancel undercount "
    "(declared B=1 observed B=0 via DLV CANCEL_STATE), Mode26 MANAGEMENT "
    "overcount (ES resume+discard=0 observed A=1). All STORAGE_CORRUPT "
    "semantic findings; faults=[]; single READ_ONLY txn; mutation 0. "
    "Same-txn: every d3s2 suffix port_trace has exactly one begin:READ_ONLY; "
    "two-txn list-then-count models fail closed (self-test tamper). "
    "Frozen 127-vector origin/main pin retained (125 + P1-D evaluator-off). "
    "P1-D2 appends Mode21 count-green without BIND set: FOCUS count "
    "complete (bit0|bit1) while binding_complete_mask=0 at BIND_ATTEMPT "
    "entry (BIND_PHASE_ACTIVE, no COMPLETE_READY, sticky 0); call-level "
    "checkpoint freezes phase/masks/flags/pass_kind/last_carrier_key + spy "
    "begin/iter_open/iter_close/trace_count; test-only "
    "probe_false_terminal_finalize on session/context copy with "
    "copy.state=EXHAUSTED expects INVALID_STATE Port0 no cleanup/output "
    "mutation; original session resumes BIND→COMPLETE/adopt1. Not orphan "
    "CORRUPT / Port fault / evaluator-off / metadata-only. "
    "Frozen 128-vector origin/main pin retained (127 + P1-D2). P1-B1 appends "
    "§18.13.15 case5 / §18.13.8 Modes22–23 only: Mode22 CLEANUP_PLAN PRESENT "
    "ordinary-skip positive (RC app>0, empty ATTEMPT band, matching DELIVERY "
    "plan → cleanup_skip=1, no ordinary undercount note, empty BIND COMPLETE/"
    "adopt1; checkpoint freezes cleanup_skip=1; Port-trace/get budget pin "
    "matching CLEANUP setup get); Mode23 matching TX CLEANUP_PLAN PRESENT "
    "still-ordinary negative (cleanup_skip forced 0; STATE PRESENT + known-"
    "slot EVIDENCE insufficient → STORAGE_CORRUPT). "
    "Frozen 130-vector origin/main pin retained (128 + P1-B1). P1-B2 appends "
    "§18.13.15 case5 residual / §18.13.8 Modes24–26 still-ordinary negatives "
    "(one formal vector each): Mode24 RC reply_count>0 + matching DELIVERY "
    "plan + REVERSE_REPLY known-kind absent → cleanup_skip=0 STORAGE_CORRUPT; "
    "Mode25 CUM total>0 + matching TX plan + RECENT required slot absent → "
    "cleanup_skip=0 STORAGE_CORRUPT; Mode26 ES resume/discard>0 + matching "
    "TX plan + MANAGEMENT empty → cleanup_skip=0 stream undercount "
    "STORAGE_CORRUPT. Modes24–26 force cleanup_skip=0 without CLEANUP setup "
    "get (plan presence via same-snapshot typed row + baseline visit; "
    "Port-trace/d3_peer_get_count pin zero extra plan get). Checkpoints "
    "freeze cleanup_skip=0 / phase FAILED / FOCUS_LIVE. Case5 Mode21 "
    "existing + 22/23 P1-B1 + 24–26 this slice aligned; D3-S2 complete not "
    "claimed. "
    "Frozen 133-vector origin/main pin retained (130 + P1-B2). P1-C1 appends "
    "§18.13.15 cases 3/19 / §18.13.12.1 Mode23: (1) all required slots 0..L "
    "coherent empty equation + extra RAW slot L+1 (D1 typed-valid slot<=8, "
    "same owner/PVD) → FOCUS counts green then BIND illegal slot "
    "STORAGE_CORRUPT (not mere D1 invalid); (2) equation fail — all slots "
    "0..L PRESENT, SUMMARY counters D1-valid, valid != M+overflow → FOCUS "
    "close CORRUPT; (3) late coherence fail — equation green, RAW "
    "MATERIALIZED late_material=1 with SUMMARY late_evidence_count=0 "
    "(D1 late_mat==(late>0) holds) → observed_c > declared_c CORRUPT "
    "(no false declared_c==observed_c requirement). Also: (4) CANCEL_FIRST "
    "+ Evidence slot0 → BIND CORRUPT after carrier get (shape exact-0); "
    "(5) multi-owner TX legal 0..L + CANCEL empty with CANCEL last FOCUS "
    "(declared_L=0) → COMPLETE (anti last-declared_L); (6) multi-owner TX "
    "legal + CANCEL slot0 with key order STATE<RC and TX EV<EV_DLV → "
    "BIND CORRUPT after legal TX secondaries. Each vector single-txn "
    "mutation_calls=0. "
    "Frozen 139-vector origin/main pin retained (133 + P1-C1 / PR#70). "
    "P1-C2 appends §18.13.15 case3 residual Modes24–25 known-slot legality: "
    "constructibility — D1 same-record already rejects reply_kind∉1..4, "
    "CUM slot≠0, RECENT slot>3 so those are not S2 formal rows; instead "
    "D1-valid declared/population shape fails: Mode24 RC reply_count=1 + "
    "zero RR undercount; Mode24 reply_count=1 + RECEIPT+DISPOSITION "
    "overcount/extra; Mode25 CUM total=1 + zero RECENT undercount; Mode25 "
    "CUM total=1 + RECENT cycle1/slot0 + cycle2/slot1 (D1 slot="
    "(cycle-1)mod4) overcount. FOCUS B6k close notes STORAGE_CORRUPT "
    "(production declared vs observed compare; no production false "
    "COMPLETE; oracle/test-only). Single-txn mutation_calls=0. "
    "Does not claim full D3-S2 oracle complete, "
    "Stage5 D3 bind, D4, public Runtime, ESP-IDF, or hardware. TEST "
    "transport begin forbidden. Independent generator — production C not "
    "invoked for expected generation."
)

SHA256_PROCEDURE = (
    "Do not embed full-file sha256 inside this artifact. Generator `check` "
    "proves deterministic rebuild equality against "
    "tools/domain_scan_crossrow_d3s2_vector_gen.py and fail-closed freezes "
    "the exact 94-vector D3-S1 prefix, the 100-vector prior main, the "
    "102-vector prior main, the 104-vector prior main, the 106-vector "
    "prior main, the 108-vector prior main, the 110-vector prior main, "
    "the 112-vector prior main, the 113-vector origin/main, the "
    "114-vector origin/main, the 115-vector origin/main, the "
    "119-vector origin/main, the 125-vector origin/main, the "
    "127-vector origin/main, the 128-vector origin/main, the "
    "130-vector origin/main, and the 133-vector origin/main "
    "(fingerprint/order/expected/rows/calls/full object equality). "
    "content_sha256 "
    "covers the document with sha256_procedure/content_sha256 fields set "
    "to empty strings before hashing."
)

# Frozen historical ownership for all pre-Mode23 suffix builders (smoke +
# Mode25/26/24). Must stay exact "12-vector" — do not interpolate live
# D3S2_SUFFIX_COUNT (that was the Mode23 append-only ownership-drift defect).
OWNERSHIP_FROZEN_106_PREFIX = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(12-vector suffix on frozen 94-prefix only)"
)
# Alias used by pre-Mode23 builders (smoke / Mode25 / Mode26 / Mode24).
OWNERSHIP_DEFAULT = OWNERSHIP_FROZEN_106_PREFIX
# Current Mode23-only ownership (14-vector suffix at Mode23 append time).
# Hardcoded 14 so a later append does not rewrite published Mode23 objects.
OWNERSHIP_MODE23 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(14-vector suffix on frozen 94-prefix only)"
)
# Current Mode22-only ownership (16-vector suffix at Mode22 append time).
# Hardcoded 16 so a later append does not rewrite published Mode22 objects.
OWNERSHIP_MODE22 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(16-vector suffix on frozen 94-prefix only)"
)
# Current Mode21-only ownership (18-vector suffix at Mode21 append time).
# Hardcoded 18 so a later append does not rewrite published Mode21 objects.
OWNERSHIP_MODE21 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(18-vector suffix on frozen 94-prefix only)"
)
# P0-A ownership (19-vector suffix at P0-A append time). Hardcoded 19 so a
# later append does not rewrite published P0-A objects.
OWNERSHIP_P0A = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(19-vector suffix on frozen 112-prefix only)"
)
# P0-B ownership (20-vector suffix at P0-B append time). Hardcoded 20 so a
# later append does not rewrite published P0-B objects.
OWNERSHIP_P0B = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(20-vector suffix on frozen 113-prefix only)"
)
# P0-C ownership (21-vector suffix at P0-C append time). Hardcoded 21 so a
# later append does not rewrite published P0-C objects.
OWNERSHIP_P0C = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(21-vector suffix on frozen 114-prefix only)"
)
# P0-D ownership (25-vector suffix at P0-D append time). Hardcoded 25 so a
# later append does not rewrite published P0-D objects.
OWNERSHIP_P0D = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(25-vector suffix on frozen 115-prefix only)"
)
# P1-A ownership (31-vector suffix at P1-A append time). Hardcoded 31 so a
# later append does not rewrite published P1-A objects.
OWNERSHIP_P1A = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(31-vector suffix on frozen 119-prefix only)"
)
# P1-D ownership (33-vector suffix at P1-D append time). Hardcoded 33 so a
# later append does not rewrite published P1-D objects.
OWNERSHIP_P1D = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(33-vector suffix on frozen 125-prefix only)"
)
# P1-D2 ownership (34-vector suffix at P1-D2 append time). Hardcoded 34 so a
# later append does not rewrite published P1-D2 objects.
OWNERSHIP_P1D2 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(34-vector suffix on frozen 127-prefix only)"
)
# P1-B1 ownership (36-vector suffix at P1-B1 append time). Hardcoded 36 so a
# later append does not rewrite published P1-B1 objects.
OWNERSHIP_P1B1 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(36-vector suffix on frozen 128-prefix only)"
)
# P1-B2 ownership (39-vector suffix at P1-B2 append time). Hardcoded 39 so a
# later append does not rewrite published P1-B2 objects.
OWNERSHIP_P1B2 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(39-vector suffix on frozen 130-prefix only)"
)
# P1-C1 ownership (45-vector suffix at P1-C1 append time). Hardcoded 45 so a
# later append does not rewrite published P1-C1 objects.
OWNERSHIP_P1C1 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(45-vector suffix on frozen 133-prefix only)"
)
# P1-C2 ownership (49-vector suffix at P1-C2 append time). Hardcoded 49 so a
# later append does not rewrite published P1-C2 objects.
OWNERSHIP_P1C2 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(49-vector suffix on frozen 139-prefix only)"
)


def _load_d3s1():
    spec = importlib.util.spec_from_file_location(
        "domain_scan_crossrow_vector_gen", D3S1_GEN_PATH
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {D3S1_GEN_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_d3s1 = _load_d3s1()


def from_hex(s: str) -> bytes:
    return _d3s1.from_hex(s)


def hex_of(b: bytes) -> str:
    return _d3s1.hex_of(b)


def content_sha256_of_doc(doc: Dict[str, Any]) -> str:
    tmp = copy.deepcopy(doc)
    tmp["sha256_procedure"] = ""
    tmp["content_sha256"] = ""
    raw = json.dumps(tmp, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def d3s1_vector_fingerprint(vec: Dict[str, Any]) -> str:
    """Prefix fingerprints must match the frozen D3-S1 generator exactly."""
    return _d3s1.vector_fingerprint(vec)


def d3s2_vector_fingerprint(vec: Dict[str, Any]) -> str:
    """Suffix fingerprint includes phase / count+binding masks."""
    exp = vec["expected"]
    payload = {
        "id": vec["id"],
        "kind": vec["kind"],
        "mode": vec["mode"],
        "candidate_binding": vec["candidate_binding"],
        "rows": vec["rows"],
        "alt_rows": vec.get("alt_rows") or {},
        "faults": vec["faults"],
        "calls": vec["calls"],
        "expected": {
            "final_status": exp.get("final_status"),
            "adopted": exp.get("adopted"),
            "state_after": exp.get("state_after"),
            "recognizable_future_seen": exp.get("recognizable_future_seen"),
            "family14_row_count": exp.get("family14_row_count"),
            "current_domain_key_count": exp.get("current_domain_key_count"),
            "ok_row_count": exp.get("ok_row_count"),
            "profile_exact_active": exp.get("profile_exact_active"),
            "profile_mismatch": exp.get("profile_mismatch"),
            "future_profile_candidate": exp.get("future_profile_candidate"),
            "profile_get_present_mask": exp.get("profile_get_present_mask"),
            "family14_iter_seen_mask": exp.get("family14_iter_seen_mask"),
            "reopen_required": exp.get("reopen_required"),
            "close_count": exp.get("close_count"),
            "mutation_calls": exp.get("mutation_calls"),
            "iter_open_count": exp.get("iter_open_count"),
            "port_trace": exp.get("port_trace"),
            "has_sticky_primary": exp.get("has_sticky_primary"),
            "sticky_primary": exp.get("sticky_primary"),
            "d3_peer_get_count": exp.get("d3_peer_get_count"),
            "d3_mode_applicable_count": exp.get("d3_mode_applicable_count"),
            "phase": exp.get("phase"),
            "count_complete_mask": exp.get("count_complete_mask"),
            "binding_complete_mask": exp.get("binding_complete_mask"),
            "flags": exp.get("flags"),
        },
    }
    # Optional note_count only when present so legacy fingerprints stay fixed.
    if "note_count" in exp:
        payload["expected"]["note_count"] = exp.get("note_count")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _walk_trace_segment(n_ok_rows: int) -> List[str]:
    """One zero-prefix full-band walk: n_ok_rows OK visits + terminal NOT_FOUND."""
    return ["iter_next"] * (n_ok_rows + 1)


def _begin_profile_port_prefix() -> List[str]:
    """begin(RO) + 17 family1–4 profile gets (docs/17 §18.13.4 baseline)."""
    return ["begin:READ_ONLY"] + ["get"] * 17


def run_d3s2_empty_carrier_case(
    mode: int, binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Independent reference model for empty-carrier / empty-secondary success.

    Models docs/17 §18.13.4/.5/.9 same-txn machine for profile-only material:
      begin_profiled_d3s2 → baseline once → sequential zero-prefix reopen →
      SELECT_CARRIER empty → BIND set(mode) empty → COMPLETE → finalize adopt.

    Does not invoke production C. Port trace / iter_open / masks match the
    closed empty-carrier production path.
    """
    if mode not in MODE_BIND_MASK:
        raise SystemExit(f"unsupported focus_mode {mode}")
    if len(rows) != 17:
        raise SystemExit(
            f"empty-carrier smoke requires exact 17 profile rows (got {len(rows)})"
        )

    n_drive = MODE_DRIVE_COUNT[mode]
    n_open = MODE_ITER_OPEN[mode]
    bind_mask = MODE_BIND_MASK[mode]
    n_ok = 17

    calls: List[Dict[str, Any]] = [
        {
            "op": "begin_profiled_d3s2",
            "mode": mode,
            "expected_status": "OK",
        }
    ]
    for _ in range(n_drive):
        calls.append(
            {
                "op": "d3s2_drive",
                "row_budget": 256,
                "expected_status": "OK",
            }
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    # Port trace: begin + 17 profile gets + n_open *(open + walk + close) + rollback
    port_trace: List[str] = _begin_profile_port_prefix()
    for _ in range(n_open):
        port_trace.append("iter_open:prefix0")
        port_trace.extend(_walk_trace_segment(n_ok))
        port_trace.append("iter_close")
    port_trace.append("rollback")

    # Baseline freezes D2 counters at 17 family14 / 17 ok / 0 current-domain.
    # INTERNAL passes do not re-increment frozen D2 counters (§18.13.5).
    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 0,
        "ok_row_count": 17,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # Empty-carrier BIND walks no secondaries → 0 peer gets.
        "d3_peer_get_count": 0,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": 0,  # no carriers closed
        "binding_complete_mask": bind_mask,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }

    # Material-induced sanity: profile rows must match candidate binding encoding.
    encoded = _d3s1.encode_all_profile_rows(binding)
    if rows != encoded:
        raise SystemExit("empty-carrier rows must equal stdlib profile encoding")

    return calls, expected


# ---------------------------------------------------------------------------
# Mode25 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _d1_catalog() -> Dict[str, Dict[str, Any]]:
    return _d3s1.load_d1()


# Process-local: D1 authority is a read-only on-disk pin (see load_d1 cache).
# Callers only read catalog entries (key_hex/value_hex/body_hex); they never
# mutate the shared catalog dict. Safe to verify once per process. Never
# shared across external CLI invocations (each process starts cold).
_D1_AUTHORITY_PIN_OK = False


def _assert_d1_authority_pin() -> None:
    """Fail-closed: D1 catalog pin must match the D3-S1 generator's pin."""
    global _D1_AUTHORITY_PIN_OK
    if _D1_AUTHORITY_PIN_OK:
        return
    cat = _d1_catalog()
    for vid in (
        D1_CUM_ID,
        D1_REC_ID,
        D1_ANCHOR_ID,
        D1_ES_ID,
        D1_ML_ID,
        D1_DLV_ID,
        D1_RC_ID,
        D1_RR_ID,
        D1_STATE_ID,
        D1_EV_SUM_MAT_ID,
        D1_EV_SUM_EMPTY_ID,
        D1_EV_RAW_UNUSED_ID,
        D1_EV_RAW_MAT_ID,
        D1_ATT_DLV_ID,
        D1_ATT_TX_ID,
        D1_AII_ID,
        D1_CP_TX_ID,
        D1_CP_DLV_ID,
    ):
        if vid not in cat:
            raise SystemExit(f"D1 authority missing required vector {vid}")
        v = cat[vid]
        if not v.get("key_hex") or not v.get("value_hex"):
            raise SystemExit(f"D1 {vid} missing key_hex/value_hex")
    if getattr(_d3s1, "D1_SHA256", None) is None:
        raise SystemExit("d3s1 module missing D1_SHA256 pin")
    raw = _d3s1.D1_VECTORS.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    if got != _d3s1.D1_SHA256:
        raise SystemExit(
            f"D1 authority pin mismatch: got {got} want {_d3s1.D1_SHA256}"
        )
    data = json.loads(_d3s1.D1_VECTORS.read_text(encoding="utf-8"))
    if data.get("format") != _d3s1.D1_FORMAT:
        raise SystemExit(f"D1 format pin mismatch: {data.get('format')}")
    if len(data["vectors"]) != _d3s1.D1_COUNT:
        raise SystemExit("D1 vector_count pin mismatch")
    _D1_AUTHORITY_PIN_OK = True


def _patch_cum_total_completed(value: bytes, total: int) -> bytes:
    """Independent body field patch: CUM total_completed_cycle_count + folded.

    RETRY CUM body (docs/17 §8.6 D1-B3l): tx16 | kind u16 | slot u16 |
    total u64 | folded u64 | … . folded = max(total-4, 0). Same-length
    envelope body replace + CRC32C trailer recompute (stdlib). Does not
    call production C.
    """
    st, body, _pvd = _d3s1.extract_envelope(value)
    if st != 0x51:
        raise SystemExit(f"CUM patch expected subtype 0x51, got {st:#x}")
    if len(body) != 84:
        raise SystemExit(f"CUM body must be exact 84, got {len(body)}")
    kind = struct.unpack_from(">H", body, 16)[0]
    slot = struct.unpack_from(">H", body, 18)[0]
    if kind != 1 or slot != 0:
        raise SystemExit(f"CUM kind/slot must be 1/0, got {kind}/{slot}")
    b = bytearray(body)
    struct.pack_into(">Q", b, 20, int(total))
    folded = 0 if total < 4 else int(total) - 4
    struct.pack_into(">Q", b, 28, folded)
    # admission-style zeros for folded==0 remain as in D1 base when total<=4
    if folded == 0:
        # cumulative_attempt..counter_saturated must be exact 0 (§8.6)
        b[36:] = bytes(len(b) - 36)
    out = bytearray(value)
    # body at fixed envelope offset 108 for current NLR1 domain framing
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        # fall back to search (should not happen for D1 typed values)
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("CUM body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    # re-parse to confirm
    _st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    got_total = struct.unpack_from(">Q", body2, 20)[0]
    got_folded = struct.unpack_from(">Q", body2, 28)[0]
    if got_total != total or got_folded != folded:
        raise SystemExit("CUM total/folded patch did not stick")
    return bytes(out)


def _mode25_material_rows(
    *, include_cum: bool, cum_total: int
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + ANCHOR [+ CUM] + RECENT rows with independent PVD patch.

    Returns (rows_sorted, named_rows, anchor_pvd).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    rec = cat[D1_REC_ID]
    cum = cat[D1_CUM_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)

    rec_key = from_hex(rec["key_hex"])
    rec_val = _d3s1.patch_pvd(from_hex(rec["value_hex"]), anchor_pvd)

    named: Dict[str, Dict[str, str]] = {
        "anchor": {"key_hex": hex_of(anchor_key), "value_hex": hex_of(anchor_val)},
        "recent": {"key_hex": hex_of(rec_key), "value_hex": hex_of(rec_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["anchor"],
        named["recent"],
    ]
    if include_cum:
        cum_key = from_hex(cum["key_hex"])
        cum_val = _patch_cum_total_completed(from_hex(cum["value_hex"]), cum_total)
        cum_val = _d3s1.patch_pvd(cum_val, anchor_pvd)
        named["cum"] = {
            "key_hex": hex_of(cum_key),
            "value_hex": hex_of(cum_val),
        }
        domain_rows.append(named["cum"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    # Lex order: profile family1–4 then domain family6 (ANCHOR 0x20 < RETRY 0x51).
    all_rows = list(profile) + sorted(
        domain_rows, key=lambda r: from_hex(r["key_hex"])
    )
    # Stable sorted full set
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd


def run_d3s2_mode25_cum_total1_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: CUM total=1 carrier + RECENT slot0 (C1) + true ANCHOR COMPLETE.

    Independent reference model (docs/17 §18.13.4/.5/.7/.9/.10):
      begin → baseline once (freeze D2) → SELECT finds CUM → FOCUS known-slot
      matrix (CUM + RECENT 0..3 presence exact_gets) → SELECT empty →
      BIND_RETRY (CUM self-carrier primary-only; RECENT carrier companion +
      primary) → COMPLETE → finalize adopt. mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode25 success expects 20 rows (17+3), got {n_ok}")
    # Drives: baseline, SELECT+FOCUS matrix, SELECT empty→BIND, BIND COMPLETE
    n_drive = 4
    n_open = 4  # begin open + 3 reopens

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE: open(from begin) + full walk + reopen(close+open)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS: open + full walk + 5 known-slot gets + reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 5)  # CUM + RECENT slots 0..3
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry: open + full walk + reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND_RETRY: open + walk with interleaved peer gets
    # Order: 17 profile + ANCHOR (next only) + CUM (next+primary get) +
    #        RECENT (next+carrier get+primary get) + NOT_FOUND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # CUM
    port_trace.append("get")  # true primary ANCHOR (CUM self-carrier)
    port_trace.append("iter_next")  # RECENT
    port_trace.append("get")  # carrier companion CUM
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + CUM + RECENT
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # FOCUS matrix 5 + BIND 3 peer exact_gets
        "d3_peer_get_count": 8,
        "d3_mode_applicable_count": 2,  # CUM + RECENT BIND secondaries
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_RETRY,
        "binding_complete_mask": MASK_RETRY,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode25 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    if rows[:17] != encoded:
        # profile subset must match (may interleave if sort differs — force check)
        prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
        if prof != encoded:
            raise SystemExit("mode25 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode25_recent_without_cum_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: RECENT + ANCHOR, no same-tx CUM → empty-carrier SELECT then
    BIND_RETRY carrier exact_get ABSENT → note_terminal_corrupt STORAGE_CORRUPT.

    Not a Port failure. abort consumes sticky. mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode25 recent-without-cum expects 19 rows (17+2), got {n_ok}"
        )
    # Drives: baseline OK, SELECT empty→BIND OK, BIND fail
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until RECENT; carrier CUM ABSENT → note stop
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # RECENT
    port_trace.append("get")  # carrier companion CUM → ABSENT finding
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ANCHOR + RECENT
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # RECENT BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding  # same default binding; profile already in rows
    return calls, expected


# ---------------------------------------------------------------------------
# P0-A Mode25 multi-owner SHA interleave + dual CUM carrier (§18.13.15 #2/#6)
# ---------------------------------------------------------------------------


def run_d3s2_mode25_bind_exact_get_port_failure_note0(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25 BIND exact_get Port terminal → sticky STORAGE, note_count=0 (H3).

    Independent reference model (docs/17 §18.13.5 B9 / §18.13.15 case11):
      Same material as Mode25 CUM+RECENT+ANCHOR success through FOCUS known-slot
      close, then BIND_RETRY first peer exact_get (CUM self-carrier true primary)
      returns IO_ERROR. Sticky NINLIL_E_STORAGE / phase FAILED; note_terminal_
      corrupt is NOT used (no undercount/orphan CORRUPT note). abort.

    Fault: get on_call = 17 baseline profile + 5 FOCUS matrix + 1 = 23.
    Peer get count includes the failed BIND get (production spy records it).
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode25 bind port-fail expects 20 rows (17+3), got {n_ok}"
        )
    n_drive = 4
    n_open = 4  # begin open + 3 reopens (abort cleanup closes last)
    # Fault on first BIND peer get after FOCUS matrix (5) and baseline (17).
    get_on_call = 17 + 5 + 1

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE",
        },
        {"op": "abort", "expected_status": "STORAGE"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode25 bind port-fail drive count drift")

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS matrix (5 gets) → reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 5)
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND: walk to CUM then first true-primary get fails (Port)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # CUM
    port_trace.append("get")  # true primary ANCHOR — Port IO_ERROR
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("mode25 bind port-fail must be single-txn")
    if port_trace.count("get") != 17 + 5 + 1:
        raise SystemExit(
            f"mode25 bind port-fail get count drift: {port_trace.count('get')}"
        )

    expected: Dict[str, Any] = {
        "final_status": "STORAGE",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + CUM + RECENT (baseline freeze)
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE",
        # FOCUS matrix 5 + failed BIND primary get 1 (spy still records get)
        "d3_peer_get_count": 6,
        "d3_mode_applicable_count": 1,  # CUM secondary reached before Port stop
        "phase": PHASE_FAILED,
        # FOCUS known-slot already closed before BIND Port fail
        "count_complete_mask": MASK_RETRY,
        "binding_complete_mask": 0,  # BIND incomplete; no note undercount
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
        # Formal reference-model only (not production call-count).
        "note_count": 0,
    }
    _ = binding
    _ = get_on_call  # mirrored in vector faults[]
    return calls, expected


def _retry_composite_key(tx: bytes, kind: int, slot: int) -> bytes:
    """Independent SHA256_COMPOSITE complete key for RETRY_SUMMARY (0x51)."""
    if len(tx) != 16:
        raise SystemExit("RETRY composite tx must be exact 16")
    return _d3s1.k_composite(
        0x51, tx + _d3s1.be16(int(kind)) + _d3s1.be16(int(slot))
    )


def _parse_retry_tx_kind_slot(value: bytes) -> Tuple[bytes, int, int]:
    """Independent RETRY body parse: (transaction_id, kind, slot)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x51:
        raise SystemExit(f"RETRY parse expected subtype 0x51, got {st:#x}")
    if len(body) not in (80, 84):
        raise SystemExit(f"RETRY body length must be 80|84, got {len(body)}")
    tx = bytes(body[0:16])
    kind = struct.unpack_from(">H", body, 16)[0]
    slot = struct.unpack_from(">H", body, 18)[0]
    return tx, int(kind), int(slot)


def _rekey_anchor_for_tx(
    template_value: bytes, tx: bytes
) -> Tuple[bytes, bytes]:
    """Rekey D1 ANCHOR template to a new transaction_id (key+body+primary).

    Independent of production C: body transaction_id and envelope primary_id
    rewritten; reservation_key_digest recomputed for the new txn (docs/17
    ANCHOR field law); CRC recomputed. Header head bytes retained from D1.
    """
    if len(tx) != 16:
        raise SystemExit("ANCHOR rekey tx must be exact 16")
    st, body, _ = _d3s1.extract_envelope(template_value)
    if st != 0x20:
        raise SystemExit(f"ANCHOR rekey expected subtype 0x20, got {st:#x}")
    b = bytearray(body)
    b[0:16] = tx
    # Walk body to reservation_key_digest (after scope/ikey + 3 digests).
    # Layout: txn16 + seq8 + sched8 + family4 + party + service + content32
    # + canon32 + event16 + gen8 + epochs/deadlines + evidence + target
    # + scope RAW16 + ikey RAW16 + seq_kd32 + im_kd32 + em_kd32 + res_kd32
    # + sched_owner_seq8 + payload_blob_kd32.
    o = 16 + 8 + 8 + 4
    o += _d3s1.PARTY_LEN
    o = _d3s1.skip_service_identity(bytes(b), o)
    o += 32 + 32  # content + canon
    o += 16  # event_id
    o += 8  # generation
    o += 16 + 8 + 16 + 8 + 8  # epochs / deadlines / grace
    o += 4 + 4  # required_evidence + target_count
    o += _d3s1.TARGET_LEN
    _scope, o = _d3s1.parse_raw16_at(bytes(b), o)
    _ikey, o = _d3s1.parse_raw16_at(bytes(b), o)
    # sequence_index_key_digest[32] + idempotency_map[32] + event_map[32]
    res_off = o + 32 + 32 + 32
    if res_off + 32 > len(b):
        raise SystemExit("ANCHOR body too short for reservation_key_digest")
    # RESERVATION owner TRANSACTION composite: be16(2) || raw16(tx)
    # (docs/17 / production transaction_anchor_fields_ok).
    res_dig = _d3s1.complete_key_digest_composite(
        _d3s1.ST_RES, _d3s1.be16(2) + _d3s1.raw16(tx)
    )
    b[res_off : res_off + 32] = res_dig
    out = bytearray(template_value)
    out[24:40] = tx  # primary_id
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("ANCHOR body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    key = _d3s1.k_id128(0x20, tx)
    # Self-check.
    st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    if st2 != 0x20 or body2[0:16] != tx:
        raise SystemExit("ANCHOR rekey did not stick")
    if body2[res_off : res_off + 32] != res_dig:
        raise SystemExit("ANCHOR reservation_key_digest rekey did not stick")
    if key != _d3s1.k_id128(0x20, tx):
        raise SystemExit("ANCHOR key identity drift")
    return key, bytes(out)


def _rekey_retry_for_tx(
    template_value: bytes,
    tx: bytes,
    *,
    kind: int,
    slot: int,
    anchor_pvd: bytes,
    cum_total: Optional[int] = None,
) -> Tuple[bytes, bytes]:
    """Rekey D1 RETRY template to new tx/kind/slot + PVD→ANCHOR (+ optional CUM total).

    Independent composite rekey; body identity fields rewritten; CRC + PVD via
    stdlib encoder/parser only (no production C).
    """
    if len(tx) != 16 or len(anchor_pvd) != 32:
        raise SystemExit("RETRY rekey: tx=16 and anchor_pvd=32 required")
    st, body, _ = _d3s1.extract_envelope(template_value)
    if st != 0x51:
        raise SystemExit(f"RETRY rekey expected subtype 0x51, got {st:#x}")
    b = bytearray(body)
    b[0:16] = tx
    struct.pack_into(">H", b, 16, int(kind))
    struct.pack_into(">H", b, 18, int(slot))
    if cum_total is not None:
        if int(kind) != RS_KIND_CUMULATIVE or int(slot) != 0:
            raise SystemExit("cum_total only valid for CUM kind=1 slot=0")
        if len(b) != 84:
            raise SystemExit("CUM body must be exact 84 for total patch")
        struct.pack_into(">Q", b, 20, int(cum_total))
        folded = 0 if int(cum_total) < 4 else int(cum_total) - 4
        struct.pack_into(">Q", b, 28, folded)
        if folded == 0:
            b[36:] = bytes(len(b) - 36)
    out = bytearray(template_value)
    out[24:40] = tx  # primary_id
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("RETRY body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    val = _d3s1.patch_pvd(bytes(out), anchor_pvd)
    key = _retry_composite_key(tx, kind, slot)
    got_tx, got_kind, got_slot = _parse_retry_tx_kind_slot(val)
    if got_tx != tx or got_kind != int(kind) or got_slot != int(slot):
        raise SystemExit("RETRY rekey identity did not stick")
    if cum_total is not None:
        _st2, body2, _ = _d3s1.extract_envelope(val)
        got_total = struct.unpack_from(">Q", body2, 20)[0]
        if got_total != int(cum_total):
            raise SystemExit("RETRY CUM total patch did not stick")
    _st3, _body3, pvd3 = _d3s1.extract_envelope(val)
    if pvd3 != anchor_pvd:
        raise SystemExit("RETRY header PVD must equal ANCHOR VALUE_DIGEST")
    return key, val


def _mode25_multi_owner_retry_order(
    tx_a: bytes, tx_b: bytes
) -> Tuple[str, Tuple[int, ...], List[Tuple[str, int, int, bytes]]]:
    """Complete-key order of 4 RETRY rows for two owners (CUM+REC each)."""
    rows: List[Tuple[str, int, int, bytes]] = []
    for owner, tx in (("A", tx_a), ("B", tx_b)):
        for kind, slot in (
            (RS_KIND_CUMULATIVE, 0),
            (RS_KIND_RECENT, 0),
        ):
            rows.append(
                (owner, int(kind), int(slot), _retry_composite_key(tx, kind, slot))
            )
    rows.sort(key=lambda r: r[3])
    owners = "".join(r[0] for r in rows)
    kinds = tuple(r[1] for r in rows)
    return owners, kinds, rows


def _owners_are_noncontiguous(owner_seq: str) -> bool:
    """True iff no owner collapses to a single contiguous run of all its rows."""
    if not owner_seq:
        return False
    from collections import Counter

    counts = Counter(owner_seq)
    if any(c < 2 for c in counts.values()):
        return False
    # Collapse runs; each owner must appear in >=2 runs for non-contiguous.
    runs: List[str] = []
    for ch in owner_seq:
        if not runs or runs[-1] != ch:
            runs.append(ch)
    run_count = Counter(runs)
    return all(run_count[o] >= 2 for o in counts)


def _select_mode25_multi_owner_tx_pair() -> Tuple[bytes, bytes]:
    """Bounded deterministic TX pair search with pinned result.

    Search: TX_A fixed to D1 default; TX_B last-byte 0..255 (≠ A). First
    ascending B that yields owner order ABAB is the pin (B_last=0x0c).
    Unlimited exploration is forbidden; this table is exact 256 candidates.
    """
    base = MODE25_MULTI_TX_A
    if len(base) != 16 or base[-1] != 0x99:
        raise SystemExit("MODE25_MULTI_TX_A pin must be D1 default ending 0x99")
    found: Optional[bytes] = None
    for last in range(256):
        if last == base[-1]:
            continue
        tx_b = base[:-1] + bytes([last])
        owners, kinds, _rows = _mode25_multi_owner_retry_order(base, tx_b)
        if owners == "ABAB" and kinds == MODE25_MULTI_KIND_ORDER_PIN:
            found = tx_b
            break
    if found is None:
        raise SystemExit("bounded TX pair search failed to find ABAB")
    if found != MODE25_MULTI_TX_B:
        raise SystemExit(
            "MODE25_MULTI_TX_B pin drift vs bounded search "
            f"(got last=0x{found[-1]:02x} want 0x{MODE25_MULTI_TX_B[-1]:02x})"
        )
    owners, kinds, _ = _mode25_multi_owner_retry_order(
        MODE25_MULTI_TX_A, MODE25_MULTI_TX_B
    )
    if owners != MODE25_MULTI_OWNER_ORDER_PIN:
        raise SystemExit("pinned multi-owner order drift")
    if kinds != MODE25_MULTI_KIND_ORDER_PIN:
        raise SystemExit("pinned multi-owner kind order drift")
    if not _owners_are_noncontiguous(owners):
        raise SystemExit("pinned multi-owner order is contiguous")
    return MODE25_MULTI_TX_A, MODE25_MULTI_TX_B


def _mode25_multi_owner_material_rows(
    *, cum_total: int = 1
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes, bytes]:
    """Build profile + 2 ANCHOR + 2 CUM + 2 RECENT for two TX owners.

    Returns (rows_sorted, named_rows, tx_a, tx_b).
    """
    _assert_d1_authority_pin()
    tx_a, tx_b = _select_mode25_multi_owner_tx_pair()
    cat = _d1_catalog()
    anc_t = from_hex(cat[D1_ANCHOR_ID]["value_hex"])
    cum_t = from_hex(cat[D1_CUM_ID]["value_hex"])
    rec_t = from_hex(cat[D1_REC_ID]["value_hex"])

    named: Dict[str, Dict[str, str]] = {}
    domain_rows: List[Dict[str, str]] = []
    for label, tx in (("A", tx_a), ("B", tx_b)):
        ak, av = _rekey_anchor_for_tx(anc_t, tx)
        apvd = _d3s1.value_digest(av)
        named[f"anchor_{label}"] = {
            "key_hex": hex_of(ak),
            "value_hex": hex_of(av),
        }
        domain_rows.append(named[f"anchor_{label}"])
        ck, cv = _rekey_retry_for_tx(
            cum_t,
            tx,
            kind=RS_KIND_CUMULATIVE,
            slot=0,
            anchor_pvd=apvd,
            cum_total=int(cum_total),
        )
        named[f"cum_{label}"] = {"key_hex": hex_of(ck), "value_hex": hex_of(cv)}
        domain_rows.append(named[f"cum_{label}"])
        rk, rv = _rekey_retry_for_tx(
            rec_t,
            tx,
            kind=RS_KIND_RECENT,
            slot=0,
            anchor_pvd=apvd,
        )
        named[f"rec_{label}"] = {"key_hex": hex_of(rk), "value_hex": hex_of(rv)}
        domain_rows.append(named[f"rec_{label}"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    # Fail-closed: body-parse RETRY owner order must be the pin (not mere count).
    retry_parsed: List[Tuple[str, int, int]] = []
    for r in all_rows:
        key = from_hex(r["key_hex"])
        if len(key) < 10 or key[8] != 6 or key[9] != 0x51:
            continue
        tx, kind, slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if tx == tx_a:
            owner = "A"
        elif tx == tx_b:
            owner = "B"
        else:
            raise SystemExit("unexpected RETRY owner tx in multi-owner material")
        retry_parsed.append((owner, kind, slot))
    if len(retry_parsed) != 4:
        raise SystemExit(f"multi-owner expects 4 RETRY rows, got {len(retry_parsed)}")
    owner_seq = "".join(o for o, _k, _s in retry_parsed)
    kind_seq = tuple(k for _o, k, _s in retry_parsed)
    if owner_seq != MODE25_MULTI_OWNER_ORDER_PIN:
        raise SystemExit(
            f"multi-owner RETRY owner order {owner_seq!r} != pin "
            f"{MODE25_MULTI_OWNER_ORDER_PIN!r}"
        )
    if kind_seq != MODE25_MULTI_KIND_ORDER_PIN:
        raise SystemExit(
            f"multi-owner RETRY kind order {kind_seq!r} != pin "
            f"{MODE25_MULTI_KIND_ORDER_PIN!r}"
        )
    if not _owners_are_noncontiguous(owner_seq):
        raise SystemExit("multi-owner RETRY rows are owner-contiguous")
    # Carriers (CUM only) must be two distinct owners in complete-key order.
    cum_owners = [o for o, k, _s in retry_parsed if k == RS_KIND_CUMULATIVE]
    if cum_owners != ["A", "B"]:
        raise SystemExit(f"CUM carrier order must be A then B, got {cum_owners}")
    return all_rows, named, tx_a, tx_b


def run_d3s2_mode25_two_owner_sha_interleave_dual_carrier_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: two CUM carriers + interleaved SHA RETRY + dual FOCUS/BIND COMPLETE.

    Independent reference model (docs/17 §18.13.3/.4/.6/.7/.9/.15 cases 2/6):
      begin → baseline once → SELECT CUM_A → FOCUS matrix → SELECT CUM_B →
      FOCUS matrix → SELECT empty → BIND_RETRY (4 secondaries) → COMPLETE.
    Port-trace pins both FOCUS matrices (5 gets each) and BIND peer gets
    (2×CUM primary + 2×RECENT carrier+primary = 6) so skip/dup cannot match.
    """
    n_ok = len(rows)
    if n_ok != 23:
        raise SystemExit(
            f"mode25 multi-owner expects 23 rows (17+6), got {n_ok}"
        )
    # Drives: baseline, SELECT+FOCUS A, SELECT+FOCUS B, SELECT empty→BIND, BIND
    n_drive = 5
    n_open = 5

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT CUM_A + FOCUS matrix (CUM + RECENT 0..3)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 5)
    port_trace.append("iter_close")
    # drive3 SELECT CUM_B + FOCUS matrix
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 5)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND entry
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_RETRY: domain order ANCHOR_B, ANCHOR_A, CUM_A, CUM_B,
    # REC_A, REC_B (complete-key). CUM self-carrier primary-only; RECENT
    # carrier companion + primary.
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR_B
    port_trace.append("iter_next")  # ANCHOR_A
    port_trace.append("iter_next")  # CUM_A
    port_trace.append("get")  # true primary ANCHOR_A
    port_trace.append("iter_next")  # CUM_B
    port_trace.append("get")  # true primary ANCHOR_B
    port_trace.append("iter_next")  # REC_A
    port_trace.append("get")  # carrier companion CUM_A
    port_trace.append("get")  # true primary ANCHOR_A
    port_trace.append("iter_next")  # REC_B
    port_trace.append("get")  # carrier companion CUM_B
    port_trace.append("get")  # true primary ANCHOR_B
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    port_trace.append("rollback")

    # FOCUS 5+5 + BIND 6 = 16 peer exact_gets (baseline 17 profile excluded).
    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 6,  # 2 ANCHOR + 2 CUM + 2 RECENT
        "ok_row_count": 23,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": 16,
        "d3_mode_applicable_count": 4,  # 4 BIND secondaries
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_RETRY,
        "binding_complete_mask": MASK_RETRY,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode25 multi-owner rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    if rows[:17] != encoded:
        prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
        if prof != encoded:
            raise SystemExit("mode25 multi-owner profile encoding mismatch")
    return calls, expected


# ---------------------------------------------------------------------------
# Mode26 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _patch_es_resume_discard(
    value: bytes, *, resume: int, discard: int
) -> bytes:
    """Independent body field patch: EVENT_SPOOL resume/discard + re-CRC.

    EVENT_SPOOL body (docs/17 §8.6 D1-B3k): exact 300; successful_resume_count
    u32 BE @260; discard_committed u32 BE @264. Same-length envelope body
    replace + CRC32C trailer recompute (stdlib). Does not call production C.
    """
    st, body, _pvd = _d3s1.extract_envelope(value)
    if st != 0x50:
        raise SystemExit(f"ES patch expected subtype 0x50, got {st:#x}")
    if len(body) != 300:
        raise SystemExit(f"ES body must be exact 300, got {len(body)}")
    if not (0 <= int(resume) <= 8):
        raise SystemExit(f"ES resume out of D1 domain 0..8: {resume}")
    if int(discard) not in (0, 1):
        raise SystemExit(f"ES discard must be 0|1, got {discard}")
    b = bytearray(body)
    struct.pack_into(">I", b, ES_RESUME_BODY_OFF, int(resume))
    struct.pack_into(">I", b, ES_DISCARD_BODY_OFF, int(discard))
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("ES body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    _st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    got_r = struct.unpack_from(">I", body2, ES_RESUME_BODY_OFF)[0]
    got_d = struct.unpack_from(">I", body2, ES_DISCARD_BODY_OFF)[0]
    if got_r != int(resume) or got_d != int(discard):
        raise SystemExit("ES resume/discard patch did not stick")
    return bytes(out)


def _parse_es_resume_discard(value: bytes) -> Tuple[int, int]:
    """Independent EVENT_SPOOL resume/discard parse (no production C)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x50 or len(body) != 300:
        raise SystemExit("ES parse: not a typed EVENT_SPOOL body")
    resume = struct.unpack_from(">I", body, ES_RESUME_BODY_OFF)[0]
    discard = struct.unpack_from(">I", body, ES_DISCARD_BODY_OFF)[0]
    return int(resume), int(discard)


def _parse_ml_tx_and_kind(value: bytes) -> Tuple[bytes, int]:
    """Independent MANAGEMENT_LEDGER body parse: (transaction_id, op_kind)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x52 or len(body) != 364:
        raise SystemExit("ML parse: not a typed MANAGEMENT_LEDGER body")
    kind = struct.unpack_from(">H", body, 16)[0]
    tx = bytes(body[ML_TX_BODY_OFF : ML_TX_BODY_OFF + 16])
    return tx, int(kind)


def _mode26_material_rows(
    *, include_es: bool, resume: int, discard: int
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + ANCHOR + MANAGEMENT [+ EVENT_SPOOL] with PVD patch.

    Returns (rows_sorted, named_rows, anchor_pvd).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    ml = cat[D1_ML_ID]
    es = cat[D1_ES_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_tx = anchor_key[13:29]
    if len(anchor_tx) != 16:
        raise SystemExit("ANCHOR ID128 identity must be exact 16")

    ml_key = from_hex(ml["key_hex"])
    ml_val = _d3s1.patch_pvd(from_hex(ml["value_hex"]), anchor_pvd)
    ml_tx, ml_kind = _parse_ml_tx_and_kind(ml_val)
    if ml_kind != ML_KIND_RESUME:
        raise SystemExit(f"Mode26 requires MANAGEMENT RESUME kind=15, got {ml_kind}")
    if ml_tx != anchor_tx:
        raise SystemExit(
            "Mode26 MANAGEMENT transaction_id must match ANCHOR/ES tx "
            f"(ml={hex_of(ml_tx)} anchor={hex_of(anchor_tx)})"
        )

    named: Dict[str, Dict[str, str]] = {
        "anchor": {"key_hex": hex_of(anchor_key), "value_hex": hex_of(anchor_val)},
        "mgmt": {"key_hex": hex_of(ml_key), "value_hex": hex_of(ml_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["anchor"],
        named["mgmt"],
    ]
    if include_es:
        es_key = from_hex(es["key_hex"])
        es_val = _patch_es_resume_discard(
            from_hex(es["value_hex"]), resume=resume, discard=discard
        )
        es_val = _d3s1.patch_pvd(es_val, anchor_pvd)
        got_r, got_d = _parse_es_resume_discard(es_val)
        if got_r != int(resume) or got_d != int(discard):
            raise SystemExit("Mode26 ES fixture resume/discard self-check fail")
        es_tx = _d3s1.extract_envelope(es_val)[1][:16]
        if es_tx != anchor_tx:
            raise SystemExit("Mode26 EVENT_SPOOL tx must match ANCHOR")
        named["es"] = {
            "key_hex": hex_of(es_key),
            "value_hex": hex_of(es_val),
        }
        domain_rows.append(named["es"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd


def run_d3s2_mode26_es_resume1_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26 stream success: ES resume=1 carrier + 1 MANAGEMENT RESUME + ANCHOR.

    Independent reference model (docs/17 §18.13.4/.5/.6/.7/.9/.10):
      begin → baseline once → SELECT finds EVENT_SPOOL → reopen FOCUS stream
      full-band (H2 on true EXHAUSTED only; observed_a=1 vs declared=1) →
      SELECT empty → BIND_MANAGEMENT (carrier ES companion get + true ANCHOR
      primary) → COMPLETE → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+reopen FOCUS; 3 FOCUS stream H2+reopen SELECT;
      4 SELECT empty→BIND; 5 BIND COMPLETE.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode26 success expects 20 rows (17+3), got {n_ok}")
    n_drive = 5
    n_open = 5

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 26, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier (full residual walk) → reopen FOCUS stream
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 FOCUS_MANAGEMENT stream (0 exact_get per secondary; H2 on EXHAUSTED)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_MANAGEMENT: carrier companion then true primary (strict order)
    # Order: 17 profile + ANCHOR + ES + MANAGEMENT(next+carrier get+primary get)
    #        + NOT_FOUND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # EVENT_SPOOL
    port_trace.append("iter_next")  # MANAGEMENT
    port_trace.append("get")  # carrier companion EVENT_SPOOL
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + ES + MANAGEMENT
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # BIND only: 1 carrier + 1 primary (FOCUS stream uses 0 exact_get)
        "d3_peer_get_count": 2,
        "d3_mode_applicable_count": 1,  # one MANAGEMENT BIND secondary
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_MANAGEMENT,
        "binding_complete_mask": MASK_MANAGEMENT,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode26 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        # profile family1–4 keys are short catalog keys
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode26 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode26_mgmt_without_es_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26: MANAGEMENT + ANCHOR, no EVENT_SPOOL → empty-carrier SELECT then
    BIND_MANAGEMENT carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary get must not run. abort; mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode26 mgmt-without-es expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 26, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until MANAGEMENT; carrier ES ABSENT → note stop
    # (primary ANCHOR get must not run after carrier ABSENT)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # MANAGEMENT
    port_trace.append("get")  # carrier companion ES → ABSENT finding
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ANCHOR + MANAGEMENT
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # MANAGEMENT BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected



def _fixture_ok_row_count(rows: List[Dict[str, str]]) -> int:
    """Count successful OK rows from fixture material (independent of production).

    Profile catalog keys (len <= 10) and domain body keys (len > 10) are both
    successful OK visits under zero-prefix full-band walks. Rejects empty keys
    and oversize keys (peer capacity 45).
    """
    n_profile = 0
    n_domain = 0
    for r in rows:
        key = from_hex(r["key_hex"])
        if len(key) < 1 or len(key) > 45:
            raise SystemExit(
                f"fixture row key length out of domain 1..45: {len(key)}"
            )
        if len(key) <= 10:
            n_profile += 1
        else:
            n_domain += 1
    total = n_profile + n_domain
    if total != len(rows):
        raise SystemExit("fixture OK-row classification length drift")
    if n_profile != 17:
        raise SystemExit(f"fixture profile OK rows must be 17, got {n_profile}")
    return total


def run_d3s2_mode26_es_mgmt_budget_mid_focus_resume(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26 B5 mid-FOCUS stream budget stop + same-iterator B6 resume.

    Independent reference model (docs/17 §18.13.5 B5/B6/B11, §18.13.15 case13):
      begin → baseline → SELECT EVENT_SPOOL → reopen FOCUS_MANAGEMENT →
      drive with row_budget == n_ok (derived from fixture OK rows) so the last
      MANAGEMENT OK is observed then budget stops before NOT_FOUND (B5:
      phase stays FOCUS_MANAGEMENT, focus_live, observed_a=1, count bit 0) →
      next drive resumes same iterator, sees NOT_FOUND, H2 closes focus (B6) →
      SELECT empty → BIND_MANAGEMENT → COMPLETE. Not a B11 session restart
      (begin_calls remains 1; no iter close/open between last OK and NOT_FOUND).

    Drive chunks (same READ_ONLY txn):
      1 BASELINE; 2 SELECT+reopen FOCUS; 3 FOCUS budget stop (checkpoint);
      4 FOCUS resume NOT_FOUND H2+reopen SELECT; 5 SELECT empty→BIND;
      6 BIND COMPLETE.
    """
    n_ok = _fixture_ok_row_count(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode26 budget-resume expects 20 OK rows (17+3), got {n_ok}"
        )
    # Derive FOCUS budget from OK-row count: stop after last OK, before NOT_FOUND.
    focus_budget = n_ok
    # ES carrier complete key length from fixture (Mode26 live EVENT_SPOOL).
    es_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x50  # EVENT_SPOOL subtype
    ]
    if len(es_rows) != 1:
        raise SystemExit(
            f"mode26 budget-resume expects exactly 1 ES carrier, got {len(es_rows)}"
        )
    es_key = from_hex(es_rows[0]["key_hex"])
    es_key_len = len(es_key)
    if es_key_len == 0 or es_key_len > 45:
        raise SystemExit(f"ES carrier key_len invalid: {es_key_len}")

    n_drive = 6
    n_open = 5

    walk = _walk_trace_segment(n_ok)  # n_ok OK + terminal NOT_FOUND
    walk_ok_only = ["iter_next"] * n_ok

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier → reopen FOCUS stream
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 FOCUS_MANAGEMENT budget stop (B5): n_ok OK, no NOT_FOUND, no close
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk_ok_only)
    cp_trace_count = len(port_trace)
    # drive4 resume same iterator: NOT_FOUND → H2 B6 close → reopen SELECT
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    # drive5 SELECT empty → BIND entry reopen
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive6 BIND_MANAGEMENT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # EVENT_SPOOL
    port_trace.append("iter_next")  # MANAGEMENT
    port_trace.append("get")  # carrier companion ES
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    # Spy counts at budget-stop checkpoint (after drive3):
    # begin open + SELECT reopen open + FOCUS reopen open = 3 opens;
    # baseline close + SELECT close = 2 closes; begin_calls = 1.
    cp_begin_calls = 1
    cp_iter_open_calls = 3
    cp_iter_close_calls = 2

    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": focus_budget,
        "expected_status": "OK",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FOCUS_MANAGEMENT,
        "cp_focus_live": 1,
        "cp_observed_a": 1,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": es_key_len,
        "cp_last_carrier_key_hex": hex_of(es_key),
        "cp_begin_calls": cp_begin_calls,
        "cp_iter_open_calls": cp_iter_open_calls,
        "cp_iter_close_calls": cp_iter_close_calls,
        "cp_trace_count": cp_trace_count,
    }

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 26, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "finalize", "expected_status": "OK"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode26 budget-resume drive count drift")

    # B5 boundary: no iter_close / iter_open / begin between last FOCUS OK and
    # the resume NOT_FOUND (same-iterator mid-pass; distinguishes B11 restart).
    # Port positions: ... open, next* n_ok | next(NF), close, open ...
    focus_open_idx = None
    for i, t in enumerate(port_trace):
        if t == "iter_open:prefix0":
            # third open is FOCUS stream (after begin-attributed open #1, SELECT #2)
            opens_before = port_trace[:i].count("iter_open:prefix0")
            if opens_before == 2:
                focus_open_idx = i
                break
    if focus_open_idx is None:
        raise SystemExit("mode26 budget-resume FOCUS open not found in trace")
    focus_ok_end = focus_open_idx + 1 + n_ok
    if port_trace[focus_open_idx + 1 : focus_ok_end] != walk_ok_only:
        raise SystemExit("mode26 budget-resume FOCUS OK segment mismatch")
    if port_trace[focus_ok_end] != "iter_next":
        raise SystemExit("mode26 budget-resume expected NOT_FOUND after budget stop")
    boundary = port_trace[focus_ok_end - 1 : focus_ok_end + 1]
    if boundary != ["iter_next", "iter_next"]:
        raise SystemExit("mode26 budget-resume boundary must be two consecutive next")
    if any(
        x in port_trace[focus_ok_end - 1 : focus_ok_end + 1]
        for x in ("iter_close", "iter_open:prefix0", "begin:READ_ONLY")
    ):
        raise SystemExit("mode26 budget-resume B5 boundary polluted")
    # Strict: no close/open/begin between last OK and NOT_FOUND (they are adjacent).
    if focus_ok_end - (focus_open_idx + n_ok) != 1:
        raise SystemExit("mode26 budget-resume index arithmetic drift")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + ES + MANAGEMENT
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": 2,
        "d3_mode_applicable_count": 1,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_MANAGEMENT,
        "binding_complete_mask": MASK_MANAGEMENT,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode26 budget-resume rows must be key-sorted")
    _ = binding
    return calls, expected


# ---------------------------------------------------------------------------
# Mode24 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _patch_rc_reply_count(value: bytes, reply_count: int) -> bytes:
    """Independent body field patch: RESULT_CACHE reply_count + re-CRC.

    RESULT_CACHE body exact 378 (docs/17 §8.5 D1-B3i). reply_count u32 BE at
    body offset 150; domain 0..4. Same-length envelope body replace + CRC32C
    trailer recompute (stdlib). Does not call production C.
    """
    st, body, _pvd = _d3s1.extract_envelope(value)
    if st != 0x41:
        raise SystemExit(f"RC patch expected subtype 0x41, got {st:#x}")
    if len(body) != 378:
        raise SystemExit(f"RC body must be exact 378, got {len(body)}")
    if not (0 <= int(reply_count) <= 4):
        raise SystemExit(f"RC reply_count out of domain 0..4: {reply_count}")
    b = bytearray(body)
    struct.pack_into(">I", b, RC_REPLY_COUNT_BODY_OFF, int(reply_count))
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("RC body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    _st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    got = struct.unpack_from(">I", body2, RC_REPLY_COUNT_BODY_OFF)[0]
    if got != int(reply_count):
        raise SystemExit("RC reply_count patch did not stick")
    return bytes(out)


def _parse_rc_reply_count_and_delivery(value: bytes) -> Tuple[int, bytes, bytes]:
    """Independent RESULT_CACHE parse: (reply_count, delivery_raw80, txn16)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x41 or len(body) != 378:
        raise SystemExit("RC parse: not a typed RESULT_CACHE body")
    raw_len = int.from_bytes(body[0:2], "big")
    if raw_len != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RC delivery raw length {raw_len} != 80")
    delivery_raw = bytes(body[2 : 2 + DLV_KEY_CONTENTS_BYTES])
    txn = bytes(body[114:130])  # after RAW16(82) + kd(32)
    reply_count = struct.unpack_from(">I", body, RC_REPLY_COUNT_BODY_OFF)[0]
    if reply_count > 4:
        raise SystemExit(f"RC reply_count out of domain: {reply_count}")
    return int(reply_count), delivery_raw, txn


def _parse_rr_kind_and_delivery(value: bytes) -> Tuple[int, bytes, bytes]:
    """Independent REVERSE_REPLY parse: (reply_kind, delivery_raw80, txn16).

    reply_key_raw:RAW16(86) = delivery:RAW16(82) || reply_kind:u32.
    Closed domain kinds 1..4 (RECEIPT=1 .. CANCEL_RESULT=4).
    """
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x42 or len(body) != 330:
        raise SystemExit("RR parse: not a typed REVERSE_REPLY body")
    reply_raw_len = int.from_bytes(body[0:2], "big")
    if reply_raw_len != 86:
        raise SystemExit(f"RR reply_key raw length {reply_raw_len} != 86")
    nested_len = int.from_bytes(body[2:4], "big")
    if nested_len != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RR nested delivery raw length {nested_len} != 80")
    delivery_raw = bytes(body[4 : 4 + DLV_KEY_CONTENTS_BYTES])
    reply_kind = struct.unpack_from(">I", body, RR_REPLY_KIND_BODY_OFF)[0]
    if not (RR_KIND_MIN <= reply_kind <= RR_KIND_MAX):
        raise SystemExit(f"RR reply_kind out of closed domain 1..4: {reply_kind}")
    # Body also stores delivery_raw:RAW16 after reply_key; require bijection.
    o = 2 + 86
    dlen = int.from_bytes(body[o : o + 2], "big")
    if dlen != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RR body delivery raw length {dlen} != 80")
    body_draw = bytes(body[o + 2 : o + 2 + DLV_KEY_CONTENTS_BYTES])
    if body_draw != delivery_raw:
        raise SystemExit("RR reply_key delivery raw != body delivery raw")
    # transaction_id follows delivery_raw:RAW16 in body (independent layout).
    txn_off = o + 2 + DLV_KEY_CONTENTS_BYTES
    txn = bytes(body[txn_off : txn_off + 16])
    return int(reply_kind), delivery_raw, txn


def _parse_delivery_raw_and_primary(value: bytes) -> Tuple[bytes, bytes, bytes]:
    """Independent DELIVERY parse: (delivery_raw80, txn16, header primary_id)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x40:
        raise SystemExit(f"DELIVERY parse expected subtype 0x40, got {st:#x}")
    d = _d3s1.parse_delivery(body)
    draw = d["delivery_raw"]
    if len(draw) != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"DELIVERY raw length {len(draw)} != 80")
    primary_id = value[24:40]
    if len(primary_id) != 16:
        raise SystemExit("DELIVERY header primary_id must be exact 16")
    return bytes(draw), bytes(d["txn"]), bytes(primary_id)


def _mode24_material_rows(
    *, include_rc: bool, reply_count: int
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + DELIVERY + REVERSE_REPLY [+ RESULT_CACHE] with PVD patch.

    Returns (rows_sorted, named_rows, delivery_value_digest).
    Independent of production C: D1 authority rows + stdlib body/PVD/CRC.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    rr = cat[D1_RR_ID]
    rc = cat[D1_RC_ID]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    # Header primary_id / CRC re-validated via independent envelope parse.
    dlv_draw, dlv_txn, dlv_primary_id = _parse_delivery_raw_and_primary(dlv_val)
    if dlv_primary_id != dlv_val[24:40]:
        raise SystemExit("DELIVERY primary_id self-check fail")
    # Key identity for COMPOSITE DELIVERY is KEY_DIGEST(raw16(delivery_raw));
    # primary_id on D1 typed rows is the key identity digest prefix (16 of 32).
    if len(dlv_key) != 45 or dlv_key[8] != 6 or dlv_key[9] != 0x40:
        raise SystemExit("DELIVERY key framing unexpected")

    rr_key = from_hex(rr["key_hex"])
    rr_val = _d3s1.patch_pvd(from_hex(rr["value_hex"]), dlv_pvd)
    rr_kind, rr_draw, rr_txn = _parse_rr_kind_and_delivery(rr_val)
    if rr_kind != RR_KIND_RECEIPT:
        raise SystemExit(
            f"Mode24 requires REVERSE_REPLY RECEIPT kind=1, got {rr_kind}"
        )
    if rr_draw != dlv_draw:
        raise SystemExit("Mode24 RR delivery_raw must match DELIVERY raw")
    if rr_txn != dlv_txn:
        raise SystemExit("Mode24 RR transaction_id must match DELIVERY txn")
    # Independent header PVD/CRC re-parse after patch.
    _st_rr, _body_rr, rr_pvd = _d3s1.extract_envelope(rr_val)
    if rr_pvd != dlv_pvd:
        raise SystemExit("Mode24 RR header PVD must equal DELIVERY VALUE_DIGEST")
    if _d3s1.domain_value_framing(rr_val) != "current":
        raise SystemExit("Mode24 RR envelope framing not current after PVD patch")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "rr": {"key_hex": hex_of(rr_key), "value_hex": hex_of(rr_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["delivery"],
        named["rr"],
    ]
    if include_rc:
        rc_key = from_hex(rc["key_hex"])
        rc_val = _patch_rc_reply_count(from_hex(rc["value_hex"]), reply_count)
        rc_val = _d3s1.patch_pvd(rc_val, dlv_pvd)
        got_rc, rc_draw, rc_txn = _parse_rc_reply_count_and_delivery(rc_val)
        if got_rc != int(reply_count):
            raise SystemExit(
                f"Mode24 RC reply_count self-check fail: {got_rc} != {reply_count}"
            )
        if rc_draw != dlv_draw:
            raise SystemExit("Mode24 RC delivery_raw must match DELIVERY raw")
        if rc_txn != dlv_txn:
            raise SystemExit("Mode24 RC transaction_id must match DELIVERY txn")
        _st_rc, _body_rc, rc_pvd = _d3s1.extract_envelope(rc_val)
        if rc_pvd != dlv_pvd:
            raise SystemExit(
                "Mode24 RC header PVD must equal DELIVERY VALUE_DIGEST"
            )
        if _d3s1.domain_value_framing(rc_val) != "current":
            raise SystemExit(
                "Mode24 RC envelope framing not current after patch"
            )
        named["rc"] = {
            "key_hex": hex_of(rc_key),
            "value_hex": hex_of(rc_val),
        }
        domain_rows.append(named["rc"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, dlv_pvd


def run_d3s2_mode24_rc_reply1_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24 known-kind success: RC reply_count=1 + RR RECEIPT + true DELIVERY.

    Independent reference model (docs/17 §18.13.4/.5/.6/.7/.9/.10 B6k):
      begin → baseline once → SELECT finds RESULT_CACHE → FOCUS known-kind
      matrix (closed reply_kind 1..4 exact_get presence only; no secondary
      stream EXHAUSTED) → count/popcount/mask close (observed=1 == declared) →
      SELECT empty → BIND_REPLY (RESULT_CACHE carrier subject + true DELIVERY
      PVD/raw) → COMPLETE → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+FOCUS matrix; 3 SELECT empty→BIND; 4 BIND COMPLETE.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode24 success expects 20 rows (17+3), got {n_ok}")
    n_drive = 4
    n_open = 4

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 24, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS known-kind: full residual walk + 4 kind presence gets
    # (closed kinds 1..4; B6k; no iterator EXHAUSTED required for close)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 4)
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND_REPLY: carrier RESULT_CACHE then true DELIVERY primary
    # Order: 17 profile + DELIVERY + RESULT_CACHE + REVERSE_REPLY
    #        (next+carrier get+primary get) + NOT_FOUND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE
    port_trace.append("iter_next")  # REVERSE_REPLY
    port_trace.append("get")  # carrier companion RESULT_CACHE
    port_trace.append("get")  # true primary DELIVERY
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # DELIVERY + RESULT_CACHE + REVERSE_REPLY
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # FOCUS matrix 4 + BIND 2 peer exact_gets
        "d3_peer_get_count": 6,
        "d3_mode_applicable_count": 1,  # one REVERSE_REPLY BIND secondary
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_REPLY,
        "binding_complete_mask": MASK_REPLY,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode24 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode24 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode24_rr_without_rc_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24: RR + DELIVERY, no RESULT_CACHE → empty-carrier SELECT then
    BIND_REPLY carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary DELIVERY get must not run. abort; mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode24 rr-without-rc expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 24, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until REVERSE_REPLY; carrier RC ABSENT → note stop
    # (primary DELIVERY get must not run after carrier ABSENT)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # REVERSE_REPLY
    port_trace.append("get")  # carrier companion RESULT_CACHE → ABSENT
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # DELIVERY + REVERSE_REPLY
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # REVERSE_REPLY BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


# ---------------------------------------------------------------------------
# Mode23 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _evidence_composite_key(owner_kind: int, owner_raw: bytes, slot: int) -> bytes:
    """Independent SHA256_COMPOSITE complete key for EVIDENCE_CELL (0x32)."""
    if len(owner_raw) != EV_OWNER_RAW_LEN:
        raise SystemExit(f"evidence owner_raw must be {EV_OWNER_RAW_LEN}")
    components = (
        _d3s1.be16(int(owner_kind))
        + _d3s1.raw16(owner_raw)
        + _d3s1.be32(int(slot))
    )
    return _d3s1.bkey(6, 0x32, 5, _d3s1.composite(0x32, components))


def _replace_evidence_body_and_crc(value: bytes, body: bytes) -> bytes:
    """Same-length envelope body replace + CRC32C trailer (stdlib only)."""
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        # Fall back: locate previous body bytes for non-canonical framing.
        st0, body0, _ = _d3s1.extract_envelope(value)
        if st0 != 0x32:
            raise SystemExit(f"evidence envelope subtype {st0:#x} != 0x32")
        idx = bytes(out).find(body0)
        if idx < 0:
            raise SystemExit("evidence body not found in envelope value")
        body_off = idx
        if len(body0) != len(body):
            raise SystemExit("evidence body length must stay fixed (734 TX)")
    if len(body) != EV_TX_BODY_LEN:
        raise SystemExit(f"TX evidence body must be {EV_TX_BODY_LEN}, got {len(body)}")
    out[body_off : body_off + len(body)] = body
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    return bytes(out)


def _parse_tx_evidence_cell(
    value: bytes,
) -> Tuple[int, int, int, bytes, int, int, int, int]:
    """Independent TX EVIDENCE parse.

    Returns (cell_kind, cell_state, slot, owner_raw16, valid, overflow,
    late_count, late_material).
    """
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x32 or len(body) != EV_TX_BODY_LEN:
        raise SystemExit("EV parse: not a typed TX EVIDENCE_CELL body")
    owner_kind = struct.unpack_from(">H", body, 0)[0]
    if owner_kind != EV_OWNER_KIND_TX:
        raise SystemExit(f"EV owner_kind must be TX=1, got {owner_kind}")
    cell_kind = struct.unpack_from(">H", body, EV_CELL_KIND_BODY_OFF)[0]
    raw_len = struct.unpack_from(">H", body, 4)[0]
    if raw_len != EV_OWNER_RAW_LEN:
        raise SystemExit(f"EV owner raw length {raw_len} != 16")
    owner_raw = bytes(body[6 : 6 + EV_OWNER_RAW_LEN])
    slot = struct.unpack_from(">I", body, EV_SLOT_BODY_OFF)[0]
    cell_state = struct.unpack_from(">H", body, EV_CELL_STATE_BODY_OFF)[0]
    late_material = struct.unpack_from(">I", body, EV_LATE_MATERIAL_BODY_OFF)[0]
    valid = struct.unpack_from(">Q", body, EV_VALID_BODY_OFF)[0]
    overflow = struct.unpack_from(">Q", body, EV_OVERFLOW_BODY_OFF)[0]
    late_count = struct.unpack_from(">Q", body, EV_LATE_COUNT_BODY_OFF)[0]
    return (
        int(cell_kind),
        int(cell_state),
        int(slot),
        owner_raw,
        int(valid),
        int(overflow),
        int(late_count),
        int(late_material),
    )


def _build_tx_evidence_value(
    *,
    template_value: bytes,
    slot: int,
    cell_kind: int,
    cell_state: int,
    valid: int = 0,
    overflow: int = 0,
    late_count: int = 0,
    late_material: int = 0,
    anchor_pvd: bytes,
) -> Tuple[bytes, bytes]:
    """Build one TX EVIDENCE complete key+value from a D1 typed template.

    Independent body field patch + composite rekey + PVD→ANCHOR + CRC.
    Does not call production C.
    """
    st, body, _ = _d3s1.extract_envelope(template_value)
    if st != 0x32 or len(body) != EV_TX_BODY_LEN:
        raise SystemExit("EV template must be TX EVIDENCE_CELL typed envelope")
    b = bytearray(body)
    owner_kind = struct.unpack_from(">H", b, 0)[0]
    if owner_kind != EV_OWNER_KIND_TX:
        raise SystemExit("EV template owner must be TRANSACTION")
    raw_len = struct.unpack_from(">H", b, 4)[0]
    if raw_len != EV_OWNER_RAW_LEN:
        raise SystemExit("EV template owner raw length must be 16")
    owner_raw = bytes(b[6 : 6 + EV_OWNER_RAW_LEN])
    struct.pack_into(">H", b, EV_CELL_KIND_BODY_OFF, int(cell_kind))
    struct.pack_into(">I", b, EV_SLOT_BODY_OFF, int(slot))
    struct.pack_into(">H", b, EV_CELL_STATE_BODY_OFF, int(cell_state))
    struct.pack_into(">I", b, EV_LATE_MATERIAL_BODY_OFF, int(late_material))
    struct.pack_into(">Q", b, EV_VALID_BODY_OFF, int(valid))
    struct.pack_into(">Q", b, EV_OVERFLOW_BODY_OFF, int(overflow))
    struct.pack_into(">Q", b, EV_LATE_COUNT_BODY_OFF, int(late_count))
    # RAW MATERIALIZED / UNUSED and SUMMARY empty require zero counters on
    # non-SUMMARY-material shapes; SUMMARY material keeps patched counters.
    if cell_kind == EV_CELL_KIND_RAW:
        struct.pack_into(">Q", b, EV_VALID_BODY_OFF, 0)
        struct.pack_into(">Q", b, 710, 0)  # exact_dup
        struct.pack_into(">Q", b, EV_OVERFLOW_BODY_OFF, 0)
        struct.pack_into(">Q", b, EV_LATE_COUNT_BODY_OFF, 0)
    val = _replace_evidence_body_and_crc(template_value, bytes(b))
    val = _d3s1.patch_pvd(val, anchor_pvd)
    if _d3s1.domain_value_framing(val) != "current":
        raise SystemExit("EV envelope framing not current after patch")
    key = _evidence_composite_key(EV_OWNER_KIND_TX, owner_raw, slot)
    # Self-check independent parse.
    ck, cs, got_slot, got_owner, got_v, got_o, got_l, got_lm = (
        _parse_tx_evidence_cell(val)
    )
    if ck != int(cell_kind) or cs != int(cell_state) or got_slot != int(slot):
        raise SystemExit("EV slot/kind/state patch did not stick")
    if got_owner != owner_raw:
        raise SystemExit("EV owner_raw identity drift")
    if cell_kind == EV_CELL_KIND_SUMMARY:
        if (got_v, got_o, got_l, got_lm) != (
            int(valid),
            int(overflow),
            int(late_count),
            int(late_material),
        ):
            raise SystemExit("EV SUMMARY counter/late_material patch fail")
        # D1 same-record: late_material == (late_evidence_count > 0)
        if int(late_material) != (1 if int(late_count) > 0 else 0):
            raise SystemExit("EV SUMMARY late_material coherence fail")
        if int(overflow) > int(valid) or int(late_count) > int(valid):
            raise SystemExit("EV SUMMARY counter domain fail")
    else:
        if (got_v, got_o, got_l) != (0, 0, 0):
            raise SystemExit("EV RAW counters must be zero")
    _st2, _body2, pvd2 = _d3s1.extract_envelope(val)
    if pvd2 != anchor_pvd:
        raise SystemExit("EV header PVD must equal ANCHOR VALUE_DIGEST")
    return key, val


def _mode23_material_rows(
    *, include_state: bool, nontrivial: bool
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes, int]:
    """Build profile + ANCHOR [+ STATE] + EVIDENCE slots for Mode23.

    Success (include_state=True, nontrivial=True): slots 0..L PRESENT with
    SUMMARY valid=2 overflow=1 late=1 and M=1 RAW MATERIALIZED (late_material=1)
    so equation valid == M + overflow and late coherence hold without false
    late equality (docs/17 §18.13.12.1 Mode23). L from accepted profile (=3).

    Orphan (include_state=False): one SUMMARY empty secondary without STATE.

    Returns (rows_sorted, named_rows, anchor_pvd, L).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    sum_mat = cat[D1_EV_SUM_MAT_ID]
    sum_empty = cat[D1_EV_SUM_EMPTY_ID]
    raw_unused = cat[D1_EV_RAW_UNUSED_ID]
    raw_mat = cat[D1_EV_RAW_MAT_ID]

    binding = _d3s1.default_binding_fields()
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(
            f"Mode23 accepted L pin drift: binding L={L} != {MODE23_ACCEPTED_L}"
        )

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        }
    }
    domain_rows: List[Dict[str, str]] = [named["anchor"]]

    if include_state:
        state_key = from_hex(state["key_hex"])
        state_val = from_hex(state["value_hex"])
        named["state"] = {
            "key_hex": hex_of(state_key),
            "value_hex": hex_of(state_val),
        }
        domain_rows.append(named["state"])

    if nontrivial and include_state:
        # SUMMARY@0: valid=2, overflow=1, late=1, late_material=1
        # RAW slot1 MATERIALIZED late_material=1 → M=1, observed_c=1
        # RAW slots 2..L UNUSED
        # Equation: 2 == 1 + 1; late: 1 <= 1 <= 2; overflow <= valid.
        sum_tmpl = from_hex(sum_mat["value_hex"])
        k0, v0 = _build_tx_evidence_value(
            template_value=sum_tmpl,
            slot=0,
            cell_kind=EV_CELL_KIND_SUMMARY,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            valid=2,
            overflow=1,
            late_count=1,
            late_material=1,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot0"] = {"key_hex": hex_of(k0), "value_hex": hex_of(v0)}
        domain_rows.append(named["ev_slot0"])

        mat_tmpl = from_hex(raw_mat["value_hex"])
        k1, v1 = _build_tx_evidence_value(
            template_value=mat_tmpl,
            slot=1,
            cell_kind=EV_CELL_KIND_RAW,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            late_material=1,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot1"] = {"key_hex": hex_of(k1), "value_hex": hex_of(v1)}
        domain_rows.append(named["ev_slot1"])

        unused_tmpl = from_hex(raw_unused["value_hex"])
        for slot in range(2, L + 1):
            ks, vs = _build_tx_evidence_value(
                template_value=unused_tmpl,
                slot=slot,
                cell_kind=EV_CELL_KIND_RAW,
                cell_state=EV_CELL_STATE_UNUSED,
                late_material=0,
                anchor_pvd=anchor_pvd,
            )
            name = f"ev_slot{slot}"
            named[name] = {"key_hex": hex_of(ks), "value_hex": hex_of(vs)}
            domain_rows.append(named[name])
    else:
        # Orphan path: single SUMMARY empty secondary (slot0) is enough for
        # BIND_EVIDENCE to note carrier ABSENT (matches Mode24/25/26 sibling
        # minimal secondary band).
        sum_tmpl = from_hex(sum_empty["value_hex"])
        k0, v0 = _build_tx_evidence_value(
            template_value=sum_tmpl,
            slot=0,
            cell_kind=EV_CELL_KIND_SUMMARY,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            valid=0,
            overflow=0,
            late_count=0,
            late_material=0,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot0"] = {"key_hex": hex_of(k0), "value_hex": hex_of(v0)}
        domain_rows.append(named["ev_slot0"])

    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd, L


def run_d3s2_mode23_tx_state_slots_equation_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23 known-slot success: STATE + ANCHOR + slots 0..L COMPLETE.

    Independent reference model (docs/17 §18.13.4/.5/.7/.9/.12.1):
      begin → baseline once → SELECT finds TRANSACTION_STATE → FOCUS
      known-slot exact_get matrix slots 0..L (B6k; not stream EXHAUSTED) →
      equation valid==M+overflow + late coherence → SELECT empty →
      BIND_EVIDENCE (STATE carrier subject + true ANCHOR PVD/raw) for each
      EVIDENCE secondary → COMPLETE → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+FOCUS matrix; 3 SELECT empty→BIND; 4 BIND COMPLETE.
    """
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"mode23 success L pin fail: {L}")
    n_cells = L + 1
    n_ok = len(rows)
    # 17 profile + ANCHOR + STATE + (L+1) EVIDENCE = 17 + 2 + 4 = 23
    if n_ok != 17 + 2 + n_cells:
        raise SystemExit(
            f"mode23 success expects {17 + 2 + n_cells} rows "
            f"(17+ANCHOR+STATE+L+1), got {n_ok}"
        )
    n_drive = 4
    n_open = 4

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS known-slot: full residual walk + (L+1) presence gets
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_cells)
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND_EVIDENCE: each EVIDENCE → STATE carrier + ANCHOR primary
    # Lex order: profile + ANCHOR(0x20) + STATE(0x22) + EVIDENCE(0x32)×(L+1)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    for _ in range(n_cells):
        port_trace.append("iter_next")  # EVIDENCE secondary
        port_trace.append("get")  # carrier companion TRANSACTION_STATE
        port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2 + n_cells,  # ANCHOR+STATE+EV×(L+1)
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # FOCUS matrix (L+1) + BIND 2 peer gets per EVIDENCE cell
        "d3_peer_get_count": n_cells + (n_cells * 2),
        "d3_mode_applicable_count": n_cells,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_EVIDENCE,
        "binding_complete_mask": MASK_EVIDENCE,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode23 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode23 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode23_evidence_without_state_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23: EVIDENCE + ANCHOR, no STATE → empty-carrier SELECT then
    BIND_EVIDENCE carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary ANCHOR get must not run. abort; mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode23 evidence-without-state expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until first EVIDENCE; carrier STATE ABSENT → note stop
    # (primary ANCHOR get must not run after carrier ABSENT)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # EVIDENCE
    port_trace.append("get")  # carrier companion STATE → ABSENT
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ANCHOR + EVIDENCE
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # one EVIDENCE BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected



# ---------------------------------------------------------------------------
# Mode22 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _parse_rc_app_attempt_and_delivery(value: bytes) -> Tuple[int, bytes, bytes]:
    """Independent RESULT_CACHE parse: (app_attempt, delivery_raw80, txn16)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x41 or len(body) != 378:
        raise SystemExit("RC parse: not a typed RESULT_CACHE body")
    raw_len = int.from_bytes(body[0:2], "big")
    if raw_len != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RC delivery raw length {raw_len} != 80")
    delivery_raw = bytes(body[2 : 2 + DLV_KEY_CONTENTS_BYTES])
    txn = bytes(body[114:130])  # after RAW16(82) + kd(32)
    app_attempt = struct.unpack_from(">I", body, RC_APP_ATTEMPT_BODY_OFF)[0]
    return int(app_attempt), delivery_raw, txn


def _parse_attempt_dlv(
    value: bytes,
) -> Tuple[int, bytes, bytes, bytes, int, bytes, bytes]:
    """Independent ATTEMPT parse for DELIVERY-owned rows.

    Returns (owner_kind, owner_raw, attempt_id, txn16, attempt_kind,
    primary_key_digest, header_pvd).
    """
    st, body, pvd = _d3s1.extract_envelope(value)
    if st != 0x31 or len(body) != ATT_BODY_LEN:
        raise SystemExit("ATT parse: not a typed ATTEMPT body 322")
    attempt_id = bytes(body[0:16])
    owner_kind = struct.unpack_from(">H", body, 16)[0]
    raw_len = struct.unpack_from(">H", body, 20)[0]
    if raw_len > 80:
        raise SystemExit(f"ATT owner raw length {raw_len} > 80")
    owner_raw = bytes(body[22 : 22 + raw_len])
    o = 22 + raw_len
    pkd = bytes(body[o : o + 32])
    o += 32
    txn = bytes(body[o : o + 16])
    o += 16
    o += 32  # target_digest
    attempt_kind = struct.unpack_from(">H", body, o)[0]
    return (
        int(owner_kind),
        owner_raw,
        attempt_id,
        txn,
        int(attempt_kind),
        pkd,
        bytes(pvd),
    )


def _attempt_composite_key(
    owner_kind: int, owner_raw: bytes, attempt_id: bytes
) -> bytes:
    """Independent SHA256_COMPOSITE complete key for ATTEMPT (0x31)."""
    if len(attempt_id) != 16:
        raise SystemExit("attempt_id must be exact 16")
    components = (
        _d3s1.be16(int(owner_kind))
        + _d3s1.raw16(owner_raw)
        + attempt_id
    )
    return _d3s1.bkey(6, 0x31, 5, _d3s1.composite(0x31, components))


def _mode22_material_rows(
    *, include_rc: bool
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + DELIVERY + ATTEMPT [+ RESULT_CACHE] with PVD patch.

    Success (include_rc=True): APPLICATION_FIRST RC app=1 + 1 DLV-owned
    COMMAND ATTEMPT + true DELIVERY. Orphan: ATTEMPT + DELIVERY, no RC.

    Returns (rows_sorted, named_rows, delivery_value_digest).
    Independent of production C: D1 authority rows + stdlib body/PVD/CRC.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    att = cat[D1_ATT_DLV_ID]
    rc = cat[D1_RC_ID]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    dlv_draw, dlv_txn, dlv_primary_id = _parse_delivery_raw_and_primary(dlv_val)
    if dlv_primary_id != dlv_val[24:40]:
        raise SystemExit("DELIVERY primary_id self-check fail")
    if len(dlv_key) != 45 or dlv_key[8] != 6 or dlv_key[9] != 0x40:
        raise SystemExit("DELIVERY key framing unexpected")
    dlv_key_digest = _d3s1.key_digest(dlv_key)

    att_key = from_hex(att["key_hex"])
    att_val = _d3s1.patch_pvd(from_hex(att["value_hex"]), dlv_pvd)
    (
        att_okind,
        att_oraw,
        att_id,
        att_txn,
        att_kind,
        att_pkd,
        att_pvd,
    ) = _parse_attempt_dlv(att_val)
    if att_okind != ATT_OWNER_KIND_DELIVERY:
        raise SystemExit(
            f"Mode22 requires DELIVERY-owned ATTEMPT, got owner_kind={att_okind}"
        )
    if att_kind != ATT_KIND_COMMAND:
        raise SystemExit(
            f"Mode22 success prefers COMMAND attempt_kind=1, got {att_kind}"
        )
    if att_oraw != dlv_draw:
        raise SystemExit("Mode22 ATT owner_raw must match DELIVERY raw")
    if att_txn != dlv_txn:
        raise SystemExit("Mode22 ATT transaction_id must match DELIVERY txn")
    if att_pkd != dlv_key_digest:
        raise SystemExit(
            "Mode22 ATT primary_key_digest must equal KEY_DIGEST(DELIVERY key)"
        )
    if att_pvd != dlv_pvd:
        raise SystemExit(
            "Mode22 ATT header PVD must equal DELIVERY VALUE_DIGEST"
        )
    if _d3s1.domain_value_framing(att_val) != "current":
        raise SystemExit("Mode22 ATT envelope framing not current after PVD patch")
    rebuilt_att_key = _attempt_composite_key(att_okind, att_oraw, att_id)
    if rebuilt_att_key != att_key:
        raise SystemExit("Mode22 ATT complete key rebuild mismatch")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "att": {"key_hex": hex_of(att_key), "value_hex": hex_of(att_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["delivery"],
        named["att"],
    ]
    if include_rc:
        rc_key = from_hex(rc["key_hex"])
        # Keep D1 app_attempt=1; only patch PVD→DELIVERY for same-txn truth.
        rc_val = _d3s1.patch_pvd(from_hex(rc["value_hex"]), dlv_pvd)
        app_n, rc_draw, rc_txn = _parse_rc_app_attempt_and_delivery(rc_val)
        if app_n != 1:
            raise SystemExit(
                f"Mode22 RC application_attempt_count must be 1, got {app_n}"
            )
        if rc_draw != dlv_draw:
            raise SystemExit("Mode22 RC delivery_raw must match DELIVERY raw")
        if rc_txn != dlv_txn:
            raise SystemExit("Mode22 RC transaction_id must match DELIVERY txn")
        _st_rc, _body_rc, rc_pvd = _d3s1.extract_envelope(rc_val)
        if rc_pvd != dlv_pvd:
            raise SystemExit(
                "Mode22 RC header PVD must equal DELIVERY VALUE_DIGEST"
            )
        if _d3s1.domain_value_framing(rc_val) != "current":
            raise SystemExit(
                "Mode22 RC envelope framing not current after PVD patch"
            )
        named["rc"] = {
            "key_hex": hex_of(rc_key),
            "value_hex": hex_of(rc_val),
        }
        domain_rows.append(named["rc"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    # SHA256_COMPOSITE ATTEMPT must appear in complete-key lex order among rows.
    att_pos = [
        i
        for i, r in enumerate(all_rows)
        if from_hex(r["key_hex"]) == att_key
    ]
    if len(att_pos) != 1:
        raise SystemExit("Mode22 ATTEMPT row missing after sort")
    return all_rows, named, dlv_pvd


def run_d3s2_mode22_rc_app1_attempt_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22 stream success: RC app=1 + DLV-owned ATTEMPT + true DELIVERY.

    Independent reference model (docs/17 §18.13.2/.4/.7/.8/.9/.12.1):
      begin → baseline once → SELECT finds RESULT_CACHE → CANCEL_STATE +
      CLEANUP_PLAN setup gets (ABSENT) → reopen FOCUS_ATTEMPT stream
      (H2 on true EXHAUSTED only; observed app=1 cancel=0 C=0) → SELECT
      empty → BIND_ATTEMPT (RC carrier subject + true DELIVERY PVD/raw +
      ATTEMPT_ID_INDEX ABSENT peer; no FOCUS_INDEX/BIND_INDEX) → COMPLETE
      → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+setup gets+reopen FOCUS; 3 FOCUS stream H2;
      4 SELECT empty→BIND; 5 BIND COMPLETE.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode22 success expects 20 rows (17+3), got {n_ok}")
    n_drive = 5
    n_open = 5

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier: full residual walk with CANCEL + CLEANUP gets
    # at RESULT_CACHE install (lex: profile + ATT + DLV + RC).
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE carrier install
    port_trace.append("get")  # CANCEL_STATE companion (ABSENT → cancel=0)
    port_trace.append("get")  # CLEANUP_PLAN gate (ABSENT → ordinary counts)
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT stream (0 exact_get per secondary; H2 on EXHAUSTED)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_ATTEMPT: carrier RC + true DELIVERY + INDEX ABSENT (strict)
    # Order: 17 profile + ATTEMPT(next+3 gets) + DELIVERY + RESULT_CACHE + NF
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ATTEMPT secondary
    port_trace.append("get")  # carrier companion RESULT_CACHE
    port_trace.append("get")  # true primary DELIVERY
    port_trace.append("get")  # pair peer ATTEMPT_ID_INDEX → ABSENT OK
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # DELIVERY + ATTEMPT + RESULT_CACHE
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # SELECT setup 2 + BIND 3 peer exact_gets (FOCUS stream uses 0)
        "d3_peer_get_count": 5,
        "d3_mode_applicable_count": 1,  # one DELIVERY-owned ATTEMPT BIND
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_ATTEMPT,  # bit0 only; C lane unused
        "binding_complete_mask": MASK_ATTEMPT,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode22 success rows must be key-sorted")
    # No ATTEMPT_ID_INDEX rows in success material (INDEX expect 0).
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("mode22 success must not include ATTEMPT_ID_INDEX")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode22 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode22_att_without_rc_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22: DLV-owned ATTEMPT + DELIVERY, no RESULT_CACHE → empty-carrier
    SELECT then BIND_ATTEMPT carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary DELIVERY get and INDEX ABSENT probe must not run.
    abort; mutation_calls=0. Port failure is not this path.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode22 att-without-rc expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until ATTEMPT; carrier RC ABSENT → note stop
    # (primary DELIVERY get and INDEX ABSENT probe must not run)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("get")  # carrier companion RESULT_CACHE → ABSENT
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # DELIVERY + ATTEMPT
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # one ATTEMPT BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


def build_d3s2_mode22_slice_vectors() -> List[Dict[str, Any]]:
    """Mode22 append-only slice (2 vectors) after the frozen 108-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) RC app=1 + DLV-owned COMMAND ATTEMPT + true DELIVERY full success
    rows_a, named_a, _pvd_a = _mode22_material_rows(include_rc=True)
    app_n, rc_draw, _rc_txn = _parse_rc_app_attempt_and_delivery(
        from_hex(named_a["rc"]["value_hex"])
    )
    (
        att_okind,
        att_oraw,
        _aid,
        _atxn,
        att_kind,
        att_pkd,
        _apvd,
    ) = _parse_attempt_dlv(from_hex(named_a["att"]["value_hex"]))
    dlv_draw, _dlv_txn, _pid = _parse_delivery_raw_and_primary(
        from_hex(named_a["delivery"]["value_hex"])
    )
    dlv_key_digest = _d3s1.key_digest(from_hex(named_a["delivery"]["key_hex"]))
    if app_n != 1 or att_kind != ATT_KIND_COMMAND:
        raise SystemExit(
            f"Mode22 success must declare app=1 COMMAND, got app={app_n} "
            f"kind={att_kind}"
        )
    if att_okind != ATT_OWNER_KIND_DELIVERY:
        raise SystemExit("Mode22 success ATTEMPT must be DELIVERY-owned")
    if not (rc_draw == att_oraw == dlv_draw):
        raise SystemExit("Mode22 success delivery raw identity mismatch")
    if att_pkd != dlv_key_digest:
        raise SystemExit("Mode22 success ATT primary_key_digest pin fail")
    # INDEX expect 0: no 0x34 rows.
    for r in rows_a:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("Mode22 success must not ship ATTEMPT_ID_INDEX")
    calls_a, exp_a = run_d3s2_mode22_rc_app1_attempt_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M22_RC_APP1_ATT_DLV_OK",
            "kind": "mode22_rc_app1_dlv_attempt_delivery_ok",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_ATT_DLV_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note=(
                    "Mode22 carrier RESULT_CACHE application_attempt_count=1 "
                    "(APPLICATION_FIRST; PVD→DELIVERY VALUE_DIGEST)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_DLV_ID,
                row=named_a["delivery"],
                expect_presence="PRESENT",
                note="true primary DELIVERY for ATTEMPT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ATT_DLV_ID,
                    row=named_a["att"],
                    expect_presence="PRESENT",
                    note=(
                        "DELIVERY-owned COMMAND ATTEMPT secondary; "
                        "PVD→DELIVERY; INDEX ABSENT peer"
                    ),
                )
            ],
            "notes": (
                "Mode22 FOCUS stream + BIND_ATTEMPT success: live "
                "RESULT_CACHE declares application_attempt_count=1 "
                "(APPLICATION_FIRST), one DELIVERY-owned COMMAND ATTEMPT "
                "same delivery raw, true DELIVERY primary. Single "
                "READ_ONLY txn; baseline once; sequential zero-prefix "
                "reopen; SELECT installs carrier with CANCEL_STATE + "
                "CLEANUP_PLAN setup gets (ABSENT); FOCUS_ATTEMPT stream "
                "closes only on true iterator EXHAUSTED (H2; observed "
                "app=1 cancel=0 C=0 MBZ); count bit0; empty SELECT then "
                "BIND proves RESULT_CACHE carrier subject + DELIVERY "
                "PVD/raw + ATTEMPT_ID_INDEX ABSENT peer (no FOCUS_INDEX / "
                "no BIND_INDEX); COMPLETE; mutation_calls=0. "
                "SHA256_COMPOSITE ATTEMPT complete-key lex sorted. D1 "
                "authority rows patched via independent Python only."
            ),
            "ownership": OWNERSHIP_MODE22,
            "expected": exp_a,
        }
    )

    # B) ATTEMPT + DELIVERY, RC absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode22_material_rows(include_rc=False)
    calls_b, exp_b = run_d3s2_mode22_att_without_rc_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT",
            "kind": "mode22_att_without_rc_carrier_absent_corrupt",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_ATT_DLV_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_DLV_ID,
                row=named_b["att"],
                expect_presence="PRESENT",
                note=(
                    "DELIVERY-owned ATTEMPT secondary without same-tx "
                    "RESULT_CACHE carrier"
                ),
            ),
            "peer_ref": _d3s1.none_ref(
                "RESULT_CACHE carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary/INDEX gets must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_b["delivery"],
                    expect_presence="PRESENT",
                    note=(
                        "true DELIVERY present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode22 empty-carrier SELECT (no RESULT_CACHE) then "
                "BIND_ATTEMPT on live DELIVERY-owned ATTEMPT: carrier "
                "companion exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary DELIVERY "
                "get and INDEX ABSENT probe must not proceed after carrier "
                "ABSENT. Not a Port failure path. abort; mutation_calls=0. "
                "Independent reference model — production C not used for "
                "expected."
            ),
            "ownership": OWNERSHIP_MODE22,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE22_SLICE_COUNT:
        raise SystemExit("mode22 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE22_KINDS:
        raise SystemExit(f"mode22 kinds inventory mismatch: {kinds}")
    return vectors


# ---------------------------------------------------------------------------
# Mode21 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _replace_domain_body_and_crc(value: bytes, body: bytes) -> bytes:
    """Same-length envelope body replace + CRC32C trailer (stdlib only)."""
    st0, body0, _ = _d3s1.extract_envelope(value)
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body0)]) != body0:
        idx = bytes(out).find(body0)
        if idx < 0:
            raise SystemExit("domain body not found in envelope value")
        body_off = idx
        if len(body0) != len(body):
            raise SystemExit("domain body length must stay fixed for patch")
    if len(body) != len(body0):
        raise SystemExit(
            f"domain body length must stay fixed ({len(body0)}), got {len(body)}"
        )
    out[body_off : body_off + len(body)] = body
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    return bytes(out)


def _patch_state_cumulative_attempts(value: bytes, cum: int) -> bytes:
    """Independent TRANSACTION_STATE cumulative_attempts u64 BE patch."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x22 or len(body) != STATE_BODY_LEN:
        raise SystemExit("STATE patch: not a typed TRANSACTION_STATE body 224")
    b = bytearray(body)
    struct.pack_into(">Q", b, STATE_CUM_ATTEMPTS_BODY_OFF, int(cum))
    out = _replace_domain_body_and_crc(value, bytes(b))
    _st2, body2, _ = _d3s1.extract_envelope(out)
    got = struct.unpack_from(">Q", body2, STATE_CUM_ATTEMPTS_BODY_OFF)[0]
    if got != int(cum):
        raise SystemExit("STATE cumulative_attempts patch did not stick")
    if _d3s1.domain_value_framing(out) != "current":
        raise SystemExit("STATE envelope framing not current after cum patch")
    return out


def _parse_state_cum_and_txn(value: bytes) -> Tuple[int, bytes]:
    """Independent STATE parse: (cumulative_attempts, transaction_id16)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x22 or len(body) != STATE_BODY_LEN:
        raise SystemExit("STATE parse: not a typed TRANSACTION_STATE body 224")
    txn = bytes(body[0:16])
    cum = struct.unpack_from(">Q", body, STATE_CUM_ATTEMPTS_BODY_OFF)[0]
    return int(cum), txn


def _parse_attempt_tx(
    value: bytes,
) -> Tuple[int, bytes, bytes, bytes, int, bytes, bytes]:
    """Independent ATTEMPT parse for TRANSACTION-owned rows.

    Returns (owner_kind, owner_raw, attempt_id, txn16, attempt_kind,
    primary_key_digest, header_pvd).
    """
    st, body, pvd = _d3s1.extract_envelope(value)
    if st != 0x31 or len(body) != ATT_TX_BODY_LEN:
        raise SystemExit("ATT TX parse: not a typed TX ATTEMPT body 258")
    attempt_id = bytes(body[0:16])
    owner_kind = struct.unpack_from(">H", body, 16)[0]
    raw_len = struct.unpack_from(">H", body, 20)[0]
    if raw_len != 16:
        raise SystemExit(f"ATT TX owner raw length {raw_len} != 16")
    owner_raw = bytes(body[22 : 22 + raw_len])
    o = 22 + raw_len
    pkd = bytes(body[o : o + 32])
    o += 32
    txn = bytes(body[o : o + 16])
    o += 16
    o += 32  # target_digest
    attempt_kind = struct.unpack_from(">H", body, o)[0]
    return (
        int(owner_kind),
        owner_raw,
        attempt_id,
        txn,
        int(attempt_kind),
        pkd,
        bytes(pvd),
    )


def _parse_attempt_id_index(
    value: bytes,
) -> Tuple[bytes, bytes, int, bytes, bytes]:
    """Independent AII parse: (attempt_id, txn, kind, record_kd, pvd)."""
    st, body, pvd = _d3s1.extract_envelope(value)
    if st != 0x34 or len(body) != AII_BODY_LEN:
        raise SystemExit("AII parse: not a typed ATTEMPT_ID_INDEX body 100")
    attempt_id = bytes(body[0:16])
    txn = bytes(body[16:32])
    kind = struct.unpack_from(">H", body, 32)[0]
    record_kd = bytes(
        body[
            AII_ATTEMPT_RECORD_KEY_DIGEST_OFF : AII_ATTEMPT_RECORD_KEY_DIGEST_OFF
            + 32
        ]
    )
    return attempt_id, txn, int(kind), record_kd, bytes(pvd)


def _mode21_material_rows(
    *, include_aii: bool, include_cleanup_plan: bool
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + ANCHOR + STATE(cum=1) + TX ATTEMPT [+ AII] [+ CP].

    Success (include_aii=True, include_cleanup_plan=False): ordinary path
    CLEANUP_PLAN ABSENT; full ATTEMPT↔INDEX bijection; true ANCHOR PVD.

    Pair-absent (include_aii=False, include_cleanup_plan=True): no AII row;
    CLEANUP_PLAN PRESENT so cleanup_skip skips ordinary C undercount and
    BIND_ATTEMPT reaches INDEX peer exact_get ABSENT (unit-test shape).

    Returns (rows_sorted, named_rows, anchor_pvd).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    att = cat[D1_ATT_TX_ID]
    aii = cat[D1_AII_ID]
    cp = cat[D1_CP_TX_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_kd = _d3s1.key_digest(anchor_key)

    state_key = from_hex(state["key_hex"])
    state_val = _patch_state_cumulative_attempts(
        from_hex(state["value_hex"]), 1
    )
    cum, state_txn = _parse_state_cum_and_txn(state_val)
    if cum != 1:
        raise SystemExit(f"Mode21 STATE cumulative_attempts must be 1, got {cum}")

    att_key = from_hex(att["key_hex"])
    att_val = _d3s1.patch_pvd(from_hex(att["value_hex"]), anchor_pvd)
    (
        att_okind,
        att_oraw,
        att_id,
        att_txn,
        att_kind,
        att_pkd,
        att_pvd,
    ) = _parse_attempt_tx(att_val)
    if att_okind != ATT_OWNER_KIND_TRANSACTION:
        raise SystemExit(
            f"Mode21 requires TX-owned ATTEMPT, got owner_kind={att_okind}"
        )
    if att_kind != ATT_KIND_COMMAND:
        raise SystemExit(
            f"Mode21 success prefers COMMAND attempt_kind=1, got {att_kind}"
        )
    if att_oraw != state_txn or att_txn != state_txn:
        raise SystemExit("Mode21 ATT owner/txn must match STATE transaction_id")
    if att_pkd != anchor_kd:
        raise SystemExit(
            "Mode21 ATT primary_key_digest must equal KEY_DIGEST(ANCHOR key)"
        )
    if att_pvd != anchor_pvd:
        raise SystemExit(
            "Mode21 ATT header PVD must equal ANCHOR VALUE_DIGEST"
        )
    if _d3s1.domain_value_framing(att_val) != "current":
        raise SystemExit("Mode21 ATT envelope framing not current after PVD patch")
    rebuilt_att_key = _attempt_composite_key(
        ATT_OWNER_KIND_TRANSACTION, att_oraw, att_id
    )
    if rebuilt_att_key != att_key:
        raise SystemExit("Mode21 ATT complete key rebuild mismatch")
    att_complete_kd = _d3s1.key_digest(att_key)

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        },
        "state": {
            "key_hex": hex_of(state_key),
            "value_hex": hex_of(state_val),
        },
        "att": {"key_hex": hex_of(att_key), "value_hex": hex_of(att_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["anchor"],
        named["state"],
        named["att"],
    ]

    if include_aii:
        aii_key = from_hex(aii["key_hex"])
        aii_val = _d3s1.patch_pvd(from_hex(aii["value_hex"]), anchor_pvd)
        aii_id, aii_txn, aii_kind, aii_rkd, aii_pvd = _parse_attempt_id_index(
            aii_val
        )
        if aii_id != att_id or aii_txn != att_txn:
            raise SystemExit("Mode21 AII attempt_id/txn must match ATTEMPT")
        if aii_kind != ATT_KIND_COMMAND:
            raise SystemExit(
                f"Mode21 AII attempt_kind must be COMMAND, got {aii_kind}"
            )
        if aii_rkd != att_complete_kd:
            raise SystemExit(
                "Mode21 AII attempt_record_key_digest must equal "
                "KEY_DIGEST(complete TX ATTEMPT key)"
            )
        if aii_pvd != anchor_pvd:
            raise SystemExit(
                "Mode21 AII header PVD must equal ANCHOR VALUE_DIGEST"
            )
        if _d3s1.domain_value_framing(aii_val) != "current":
            raise SystemExit(
                "Mode21 AII envelope framing not current after PVD patch"
            )
        named["aii"] = {
            "key_hex": hex_of(aii_key),
            "value_hex": hex_of(aii_val),
        }
        domain_rows.append(named["aii"])

    if include_cleanup_plan:
        # Presence-only gate; D1 CP is keyed by CLEANUP subject TRANSACTION
        # (kind=2) || KEY_DIGEST(ANCHOR complete key) — already matches.
        named["cp"] = {
            "key_hex": cp["key_hex"],
            "value_hex": cp["value_hex"],
        }
        domain_rows.append(named["cp"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    # SHA256_COMPOSITE ATTEMPT must appear in complete-key lex order.
    att_pos = [
        i
        for i, r in enumerate(all_rows)
        if from_hex(r["key_hex"]) == att_key
    ]
    if len(att_pos) != 1:
        raise SystemExit("Mode21 ATTEMPT row missing after sort")
    return all_rows, named, anchor_pvd


def run_d3s2_mode21_state_cum1_att_aii_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21 stream success: STATE cum=1 + TX ATT + AII + true ANCHOR.

    Independent reference model (docs/17 §18.13.2/.4/.7/.8/.9/.12.1):
      begin → baseline once → SELECT finds TRANSACTION_STATE → CANCEL_STATE
      + CLEANUP_PLAN setup gets (ABSENT → cancel=0 ordinary counts) →
      reopen FOCUS_ATTEMPT stream (H2; observed A=1 B=0) → reopen
      FOCUS_INDEX stream (H2; observed C=1; declared C=A+B) → SELECT empty
      → BIND_ATTEMPT (STATE carrier subject + true ANCHOR PVD/raw + INDEX
      PRESENT pair body bijection) → BIND_INDEX (ANCHOR primary + ATTEMPT
      PRESENT pair; no STATE companion re-get) → COMPLETE → finalize adopt.
      mutation_calls=0. Get budget: ATTEMPT ≤3, INDEX ≤2.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+setup gets+reopen FOCUS; 3 FOCUS_ATTEMPT H2;
      4 FOCUS_INDEX H2; 5 SELECT empty→BIND; 6 BIND_ATTEMPT; 7 BIND_INDEX.
    """
    n_ok = len(rows)
    if n_ok != 21:
        raise SystemExit(
            f"mode21 success expects 21 rows (17+4), got {n_ok}"
        )
    n_drive = 7
    n_open = 7
    walk = _walk_trace_segment(n_ok)

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 21, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier: lex profile + ANCHOR + STATE install + ATT + AII
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE carrier install
    port_trace.append("get")  # CANCEL_STATE companion (ABSENT → cancel=0)
    port_trace.append("get")  # CLEANUP_PLAN gate (ABSENT → ordinary counts)
    port_trace.append("iter_next")  # ATTEMPT residual
    port_trace.append("iter_next")  # AII residual
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT stream (0 exact_get; H2 on EXHAUSTED)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 FOCUS_INDEX stream (0 exact_get; H2 on EXHAUSTED)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive6 BIND_ATTEMPT: STATE carrier + ANCHOR primary + INDEX PRESENT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATTEMPT secondary
    port_trace.append("get")  # carrier companion TRANSACTION_STATE
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("get")  # pair peer ATTEMPT_ID_INDEX PRESENT
    port_trace.append("iter_next")  # AII
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive7 BIND_INDEX: ANCHOR primary + ATTEMPT PRESENT (no STATE re-get)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("iter_next")  # AII secondary
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("get")  # pair peer ATTEMPT PRESENT
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 4,  # ANCHOR + STATE + ATT + AII
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # SELECT setup 2 + BIND_ATTEMPT 3 + BIND_INDEX 2
        "d3_peer_get_count": 7,
        "d3_mode_applicable_count": 2,  # one ATT + one AII BIND secondary
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "binding_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode21 success rows must be key-sorted")
    # Must ship exactly one AII; no CLEANUP_PLAN on ordinary path.
    aii_n = 0
    cp_n = 0
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            aii_n += 1
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x63:
            cp_n += 1
    if aii_n != 1:
        raise SystemExit(f"mode21 success must ship exact 1 AII, got {aii_n}")
    if cp_n != 0:
        raise SystemExit("mode21 success ordinary path must not ship CLEANUP_PLAN")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode21 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode21_att_without_aii_index_pair_absent_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21: STATE+ANCHOR+ATT without AII, CLEANUP_PLAN PRESENT.

    Ordinary declared C=1 would undercount at FOCUS_INDEX (observed C=0)
    before BIND. Unit-test constructible path uses CLEANUP_PLAN PRESENT so
    cleanup_skip=1 skips ordinary A/B/C compare; BIND_ATTEMPT still runs and
    notes INDEX peer exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. BIND_INDEX must not run after sticky. abort;
    mutation_calls=0. Port failure is not this path.
    """
    n_ok = len(rows)
    if n_ok != 21:
        raise SystemExit(
            f"mode21 pair-absent expects 21 rows (17+4: ANCHOR+STATE+ATT+CP), "
            f"got {n_ok}"
        )
    n_drive = 6
    n_open = 6
    walk = _walk_trace_segment(n_ok)

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 21, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT: profile + ANCHOR + STATE + ATT + CP; CLEANUP PRESENT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE carrier install
    port_trace.append("get")  # CANCEL_STATE ABSENT → cancel=0
    port_trace.append("get")  # CLEANUP_PLAN PRESENT → cleanup_skip=1
    port_trace.append("iter_next")  # ATTEMPT residual
    port_trace.append("iter_next")  # CLEANUP_PLAN residual
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT (cleanup_skip ordinary A/B)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 FOCUS_INDEX (cleanup_skip ordinary C undercount)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 SELECT empty → BIND entry
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive6 BIND_ATTEMPT: STATE + ANCHOR then INDEX ABSENT → note stop
    # (BIND_INDEX must not run)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATTEMPT secondary
    port_trace.append("get")  # carrier companion TRANSACTION_STATE
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("get")  # pair peer ATTEMPT_ID_INDEX → ABSENT note
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 4,  # ANCHOR + STATE + ATT + CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # SELECT setup 2 + BIND 3 (carrier + primary + INDEX ABSENT)
        "d3_peer_get_count": 5,
        "d3_mode_applicable_count": 1,  # one ATTEMPT BIND secondary that failed
        "phase": PHASE_FAILED,
        # cleanup_skip still sets count bits on FOCUS close for both streams
        "count_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    # Must not include AII; must include CLEANUP_PLAN.
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("mode21 pair-absent must not ship ATTEMPT_ID_INDEX")
    cp_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    ]
    if len(cp_rows) != 1:
        raise SystemExit(
            f"mode21 pair-absent must ship exact 1 CLEANUP_PLAN, got "
            f"{len(cp_rows)}"
        )
    _ = binding
    return calls, expected


def build_d3s2_mode21_slice_vectors() -> List[Dict[str, Any]]:
    """Mode21 append-only slice (2 vectors) after the frozen 110-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) STATE cum=1 + TX COMMAND ATTEMPT + AII + true ANCHOR full success
    rows_a, named_a, _pvd_a = _mode21_material_rows(
        include_aii=True, include_cleanup_plan=False
    )
    cum, state_txn = _parse_state_cum_and_txn(
        from_hex(named_a["state"]["value_hex"])
    )
    (
        att_okind,
        att_oraw,
        att_id,
        att_txn,
        att_kind,
        att_pkd,
        _apvd,
    ) = _parse_attempt_tx(from_hex(named_a["att"]["value_hex"]))
    aii_id, aii_txn, aii_kind, aii_rkd, _aipvd = _parse_attempt_id_index(
        from_hex(named_a["aii"]["value_hex"])
    )
    anchor_kd = _d3s1.key_digest(from_hex(named_a["anchor"]["key_hex"]))
    att_kd = _d3s1.key_digest(from_hex(named_a["att"]["key_hex"]))
    if cum != 1 or att_kind != ATT_KIND_COMMAND:
        raise SystemExit(
            f"Mode21 success must declare cum=1 COMMAND, got cum={cum} "
            f"kind={att_kind}"
        )
    if att_okind != ATT_OWNER_KIND_TRANSACTION:
        raise SystemExit("Mode21 success ATTEMPT must be TRANSACTION-owned")
    if not (att_oraw == att_txn == state_txn == aii_txn):
        raise SystemExit("Mode21 success txn identity mismatch")
    if att_id != aii_id or aii_kind != ATT_KIND_COMMAND:
        raise SystemExit("Mode21 success AII/ATT attempt identity mismatch")
    if att_pkd != anchor_kd:
        raise SystemExit("Mode21 success ATT primary_key_digest pin fail")
    if aii_rkd != att_kd:
        raise SystemExit("Mode21 success AII record complete-key digest pin fail")
    calls_a, exp_a = run_d3s2_mode21_state_cum1_att_aii_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK",
            "kind": "mode21_state_cum1_att_tx_aii_anchor_ok",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_ID, D1_AII_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_a["state"],
                expect_presence="PRESENT",
                note=(
                    "Mode21 carrier TRANSACTION_STATE cumulative_attempts=1 "
                    "(body field patched; cancel=0 via CANCEL_STATE ABSENT; "
                    "ordinary CLEANUP_PLAN ABSENT path)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for ATTEMPT/INDEX BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ATT_TX_ID,
                    row=named_a["att"],
                    expect_presence="PRESENT",
                    note=(
                        "TX-owned COMMAND ATTEMPT secondary; PVD→ANCHOR; "
                        "INDEX PRESENT pair peer"
                    ),
                ),
                _d3s1.d1_ref_from_id(
                    D1_AII_ID,
                    row=named_a["aii"],
                    expect_presence="PRESENT",
                    note=(
                        "ATTEMPT_ID_INDEX secondary; attempt_record_key_digest "
                        "= KEY_DIGEST(complete TX ATTEMPT key); PVD→ANCHOR"
                    ),
                ),
            ],
            "notes": (
                "Mode21 FOCUS_ATTEMPT+FOCUS_INDEX + BIND_ATTEMPT+BIND_INDEX "
                "success: live TRANSACTION_STATE declares "
                "cumulative_attempts=1 (cancel=0), one TX-owned COMMAND "
                "ATTEMPT, matching ATTEMPT_ID_INDEX, true ANCHOR primary. "
                "Single READ_ONLY txn; baseline once; sequential zero-prefix "
                "reopen; SELECT installs carrier with CANCEL_STATE + "
                "CLEANUP_PLAN setup gets (ABSENT ordinary path); "
                "FOCUS_ATTEMPT then FOCUS_INDEX streams close only on true "
                "iterator EXHAUSTED (H2; observed A=1 B=0 C=1; declared "
                "C=A+B); count bit0|bit1; empty SELECT then BIND_ATTEMPT "
                "proves STATE carrier subject + ANCHOR PVD/raw + INDEX "
                "PRESENT pair (attempt_id/txn/complete-key digest); "
                "BIND_INDEX proves ANCHOR + ATTEMPT PRESENT pair without "
                "STATE companion re-get; COMPLETE; mutation_calls=0. "
                "Get budget ATTEMPT≤3 INDEX≤2. SHA256_COMPOSITE ATTEMPT "
                "complete-key lex sorted. D1 authority rows patched via "
                "independent Python only."
            ),
            "ownership": OWNERSHIP_MODE21,
            "expected": exp_a,
        }
    )

    # B) STATE+ANCHOR+ATT, no AII, CP PRESENT → BIND INDEX ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode21_material_rows(
        include_aii=False, include_cleanup_plan=True
    )
    calls_b, exp_b = run_d3s2_mode21_att_without_aii_index_pair_absent_corrupt(
        binding, rows_b
    )
    vectors.append(
        {
            "id": "D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT",
            "kind": "mode21_att_without_aii_index_pair_absent_corrupt",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_ID, D1_ANCHOR_ID, D1_CP_TX_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_TX_ID,
                row=named_b["att"],
                expect_presence="PRESENT",
                note=(
                    "TX-owned ATTEMPT secondary without matching "
                    "ATTEMPT_ID_INDEX peer key"
                ),
            ),
            "peer_ref": _d3s1.none_ref(
                "ATTEMPT_ID_INDEX pair peer exact_get ABSENT "
                "(P1-3 constructible pair fail; BIND_INDEX must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_STATE_ID,
                    row=named_b["state"],
                    expect_presence="PRESENT",
                    note="carrier STATE cum=1 present (declared C would be 1)",
                ),
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note="true ANCHOR proven on BIND_ATTEMPT before pair ABSENT",
                ),
                _d3s1.d1_ref_from_id(
                    D1_CP_TX_ID,
                    row=named_b["cp"],
                    expect_presence="PRESENT",
                    note=(
                        "CLEANUP_PLAN PRESENT → cleanup_skip so ordinary "
                        "FOCUS INDEX undercount does not preempt BIND pair proof"
                    ),
                ),
            ],
            "notes": (
                "Mode21 constructible INDEX pair ABSENT: STATE+ANCHOR+TX "
                "ATTEMPT exist but ATTEMPT_ID_INDEX is missing. Ordinary "
                "path would fail FOCUS_INDEX undercount (declared C=1, "
                "observed C=0) before BIND; fixture uses CLEANUP_PLAN "
                "PRESENT (same shape as unit test "
                "test_d3s2_p1_mode21_bind_index_pair_absent) so cleanup_skip "
                "defers ordinary A/B/C compare and BIND_ATTEMPT reaches "
                "INDEX peer exact_get ABSENT → note_terminal_corrupt "
                "STORAGE_CORRUPT sticky/FAILED. BIND_INDEX and further "
                "pair gets must not run. Not a Port failure path. abort; "
                "mutation_calls=0. Independent reference model — production "
                "C not used for expected."
            ),
            "ownership": OWNERSHIP_MODE21,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE21_SLICE_COUNT:
        raise SystemExit("mode21 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE21_KINDS:
        raise SystemExit(f"mode21 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_smoke_vectors() -> List[Dict[str, Any]]:
    """First 6-session Mode21..26 empty-carrier product smoke (frozen pin)."""
    binding = _d3s1.default_binding_fields()
    rows = _d3s1.encode_all_profile_rows(binding)
    vectors: List[Dict[str, Any]] = []
    for mode in range(21, 27):
        kind = f"mode{mode}_empty_carrier_empty_secondary_ok"
        vid = f"D3S2_M{mode}_EMPTY_CARRIER_EMPTY_SECONDARY"
        calls, expected = run_d3s2_empty_carrier_case(mode, binding, rows)
        vec: Dict[str, Any] = {
            "id": vid,
            "kind": kind,
            "mode": mode,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows),
            "alt_rows": {},
            "faults": [],
            "calls": calls,
            "d1_refs": [],
            "source_ref": _d3s1.none_ref(
                "empty-carrier: no source secondary"
            ),
            "peer_ref": _d3s1.none_ref("empty-carrier: no peer get"),
            "row_refs": [],
            "notes": (
                f"D3-S2 product smoke Mode{mode}: empty-carrier + empty-secondary "
                f"success session. Single begin_profiled_d3s2; one READ_ONLY txn; "
                f"baseline once; sequential zero-prefix reopen; BIND set({mode}) "
                f"empty walks then COMPLETE; mutation_calls=0. Independent of other "
                f"modes (not a 6-mode single session)."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": expected,
        }
        vectors.append(vec)
    if len(vectors) != D3S2_SMOKE_COUNT:
        raise SystemExit("smoke suffix count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_SMOKE_KINDS:
        raise SystemExit(f"smoke kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode25_slice_vectors() -> List[Dict[str, Any]]:
    """Mode25 append-only slice (2 vectors) after the frozen 100-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) CUM total=1 + RECENT C1 + true ANCHOR full success
    rows_a, named_a, _pvd_a = _mode25_material_rows(include_cum=True, cum_total=1)
    calls_a, exp_a = run_d3s2_mode25_cum_total1_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK",
            "kind": "mode25_cum_total1_recent_slot1_anchor_ok",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_CUM_ID, D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named_a["cum"],
                expect_presence="PRESENT",
                note="Mode25 carrier CUM total=1 (body total field patched; PVD→ANCHOR)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for CUM/RECENT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_REC_ID,
                    row=named_a["recent"],
                    expect_presence="PRESENT",
                    note="RECENT cycle1/slot0 companion; PVD→ANCHOR",
                )
            ],
            "notes": (
                "Mode25 FOCUS known-slot + BIND_RETRY success: CUMULATIVE "
                "total_completed_cycle_count=1 carrier, RECENT C1 (slot0) "
                "companion, true ANCHOR primary. Single READ_ONLY txn; baseline "
                "once; sequential zero-prefix reopen; CUM self-carrier; RECENT "
                "carrier companion; both rows primary PVD/raw; COMPLETE; "
                "mutation_calls=0. D1 authority rows patched via independent "
                "Python encoder/parser only."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_a,
        }
    )

    # B) RECENT + ANCHOR, CUM absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode25_material_rows(
        include_cum=False, cum_total=0
    )
    calls_b, exp_b = run_d3s2_mode25_recent_without_cum_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT",
            "kind": "mode25_recent_without_cum_carrier_absent_corrupt",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_REC_ID,
                row=named_b["recent"],
                expect_presence="PRESENT",
                note="RECENT secondary without same-tx CUM carrier",
            ),
            "peer_ref": _d3s1.none_ref(
                "CUM carrier companion exact_get ABSENT (real S2 orphan finding)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note="true ANCHOR present but unused after carrier ABSENT note",
                )
            ],
            "notes": (
                "Mode25 empty-carrier SELECT (no CUMULATIVE) then BIND_RETRY on "
                "live RECENT: carrier companion exact_get ABSENT is a real S2 "
                "orphan finding via note_terminal_corrupt → STORAGE_CORRUPT. "
                "Not a Port failure path. abort; mutation_calls=0. Independent "
                "reference model — production C not used for expected."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE25_SLICE_COUNT:
        raise SystemExit("mode25 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE25_KINDS:
        raise SystemExit(f"mode25 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_p0a_slice_vectors() -> List[Dict[str, Any]]:
    """P0-A append-only slice (1 vector) after the frozen 112-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    rows, named, tx_a, tx_b = _mode25_multi_owner_material_rows(cum_total=1)
    if tx_a != MODE25_MULTI_TX_A or tx_b != MODE25_MULTI_TX_B:
        raise SystemExit("P0-A material TX pair pin drift")
    calls, exp = run_d3s2_mode25_two_owner_sha_interleave_dual_carrier_success(
        binding, rows
    )
    vectors.append(
        {
            "id": "D3S2_M25_TWO_OWNER_SHA_INTERLEAVE_DUAL_CARRIER_OK",
            "kind": "mode25_two_owner_sha_interleave_dual_carrier_ok",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows),
            "alt_rows": {},
            "faults": [],
            "calls": calls,
            "d1_refs": [D1_CUM_ID, D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named["cum_A"],
                expect_presence="PRESENT",
                note=(
                    "Mode25 multi-owner CUM_A total=1 carrier (first SELECT); "
                    "TX rekeyed from D1 authority; PVD→ANCHOR_A"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named["cum_B"],
                expect_presence="PRESENT",
                note=(
                    "Mode25 multi-owner CUM_B total=1 carrier (second SELECT); "
                    "TX_B pin last-byte 0x0c; PVD→ANCHOR_B"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_REC_ID,
                    row=named["rec_A"],
                    expect_presence="PRESENT",
                    note="RECENT A cycle1/slot0; PVD→ANCHOR_A",
                ),
                _d3s1.d1_ref_from_id(
                    D1_REC_ID,
                    row=named["rec_B"],
                    expect_presence="PRESENT",
                    note="RECENT B cycle1/slot0; PVD→ANCHOR_B",
                ),
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named["anchor_A"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR_A (TX D1 default)",
                ),
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named["anchor_B"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR_B (TX pin ...0c)",
                ),
            ],
            "notes": (
                "P0-A formal (§18.13.15 cases 2/6): Mode25 two transaction "
                "owners each with CUMULATIVE total=1 + RECENT C1 + true ANCHOR. "
                "Four SHA256_COMPOSITE RETRY secondaries in complete-key order "
                "ABAB (non-contiguous owners; kinds CUM,CUM,REC,REC). SELECT_"
                "CARRIER selects both CUM carriers exactly once (A then B) under "
                "last_carrier_key frontier; each FOCUS known-slot matrix + "
                "BIND_RETRY complete. Port-trace pins 2×5 FOCUS gets + 6 BIND "
                "peer gets (d3_peer_get_count=16). Single READ_ONLY txn; "
                "baseline once; mutation_calls=0. D1 authority rows rekeyed via "
                "independent Python only. Not D3-S2 complete claim."
            ),
            "ownership": OWNERSHIP_P0A,
            "expected": exp,
        }
    )

    if len(vectors) != D3S2_P0A_SLICE_COUNT:
        raise SystemExit("p0a slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P0A_KINDS:
        raise SystemExit(f"p0a kinds inventory mismatch: {kinds}")
    return vectors



def build_d3s2_p0b_slice_vectors() -> List[Dict[str, Any]]:
    """P0-B append-only slice (1 vector) after the frozen 113-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    rows, named, _pvd = _mode26_material_rows(
        include_es=True, resume=1, discard=0
    )
    es_r, es_d = _parse_es_resume_discard(from_hex(named["es"]["value_hex"]))
    if es_r != 1 or es_d != 0:
        raise SystemExit(
            f"P0-B Mode26 ES must declare resume=1 discard=0, got {es_r}/{es_d}"
        )
    n_ok = _fixture_ok_row_count(rows)
    if n_ok != 20:
        raise SystemExit(f"P0-B fixture OK rows must be 20, got {n_ok}")
    calls, exp = run_d3s2_mode26_es_mgmt_budget_mid_focus_resume(binding, rows)
    # Fail-closed: focus budget must equal derived OK-row count (not a magic 20).
    focus_drives = [
        c for c in calls if c["op"] == "d3s2_drive" and int(c.get("has_checkpoint", 0)) == 1
    ]
    if len(focus_drives) != 1:
        raise SystemExit("P0-B expects exactly one checkpoint drive")
    if int(focus_drives[0]["row_budget"]) != n_ok:
        raise SystemExit(
            f"P0-B focus row_budget {focus_drives[0]['row_budget']} != n_ok {n_ok}"
        )
    vectors.append(
        {
            "id": "D3S2_M26_ES_MGMT_BUDGET_MID_FOCUS_RESUME_OK",
            "kind": "mode26_es_mgmt_budget_mid_focus_resume_ok",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows),
            "alt_rows": {},
            "faults": [],
            "calls": calls,
            "d1_refs": [D1_ES_ID, D1_ML_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ES_ID,
                row=named["es"],
                expect_presence="PRESENT",
                note=(
                    "Mode26 carrier EVENT_SPOOL successful_resume_count=1 "
                    "discard_committed=0; last_carrier_key at B5 checkpoint"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for MANAGEMENT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ML_ID,
                    row=named["mgmt"],
                    expect_presence="PRESENT",
                    note=(
                        "MANAGEMENT RESUME secondary; last OK under FOCUS "
                        "budget stop (observed_a=1) before NOT_FOUND"
                    ),
                )
            ],
            "notes": (
                "P0-B formal (§18.13.15 case13 / §18.13.5 B5/B6/B11): Mode26 "
                "stream success material (ES resume=1 + MANAGEMENT RESUME + "
                "true ANCHOR). BASELINE+SELECT complete with large budget; "
                "FOCUS_MANAGEMENT uses row_budget=n_ok (derived from fixture "
                "OK-row classification, not a magic constant) so advance "
                "observes the last MANAGEMENT OK then budget-stops before "
                "NOT_FOUND. Call-level checkpoint compares production phase/"
                "focus_live/observed/masks/flags/pass_kind/cleanup_skip/"
                "last_carrier_key_len (+ exact ES complete key) and spy "
                "begin/iter_open/iter_close/trace_count. Next d3s2_drive "
                "resumes the same iterator (B6 H2 close); no mid-boundary "
                "iter_close/iter_open/begin (not B11 restart). Final SELECT "
                "empty→BIND→COMPLETE matches one-shot Mode26 success. Single "
                "READ_ONLY txn; mutation_calls=0. Independent Python only. "
                "Not D3-S2 complete claim."
            ),
            "ownership": OWNERSHIP_P0B,
            "expected": exp,
        }
    )

    if len(vectors) != D3S2_P0B_SLICE_COUNT:
        raise SystemExit("p0b slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P0B_KINDS:
        raise SystemExit(f"p0b kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_p0c_slice_vectors() -> List[Dict[str, Any]]:
    """P0-C append-only slice (1 vector) after the frozen 114-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    rows, named, _pvd = _mode25_material_rows(include_cum=True, cum_total=1)
    calls, exp = run_d3s2_mode25_bind_exact_get_port_failure_note0(binding, rows)
    if int(exp.get("note_count", -1)) != 0:
        raise SystemExit("P0-C expected note_count must be 0")
    if exp.get("sticky_primary") != "STORAGE":
        raise SystemExit("P0-C sticky must be STORAGE (not CORRUPT note path)")
    if exp["port_trace"].count("begin:READ_ONLY") != 1:
        raise SystemExit("P0-C port_trace must be single-txn")
    get_on_call = 17 + 5 + 1
    vectors.append(
        {
            "id": "D3S2_M25_BIND_EXACT_GET_PORT_FAILURE_NOTE0",
            "kind": "mode25_bind_exact_get_port_failure_note0",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows),
            "alt_rows": {},
            "faults": [
                {
                    "op": "get",
                    "on_call": get_on_call,
                    "status": "IO_ERROR",
                    "shape": "natural",
                }
            ],
            "calls": calls,
            "d1_refs": [D1_CUM_ID, D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named["cum"],
                expect_presence="PRESENT",
                note=(
                    "Mode25 CUM carrier; BIND first peer get is true-primary "
                    "ANCHOR (self-carrier path) where Port IO_ERROR injects"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named["anchor"],
                expect_presence="PRESENT",
                note="true primary target of failing BIND exact_get (Port path)",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_REC_ID,
                    row=named["recent"],
                    expect_presence="PRESENT",
                    note="RECENT present after FOCUS close; not reached in BIND",
                )
            ],
            "notes": (
                "P0-C formal (§18.13.15 cases 7 remaining / 11 / §18.13.5 B9 H3): "
                "Mode25 success material through FOCUS known-slot close, then "
                "BIND exact_get Port IO_ERROR on first peer get (CUM self-carrier "
                "true primary). sticky STORAGE / phase FAILED / note_count=0 — "
                "must not fabricate undercount or orphan via note_terminal_corrupt "
                "(sticky is STORAGE not STORAGE_CORRUPT). Real spy fault "
                "get on_call=23 (17 profile + 5 FOCUS + 1). Single READ_ONLY "
                "txn; abort; mutation_calls=0. Independent Python only. Not "
                "D3-S2 complete claim."
            ),
            "ownership": OWNERSHIP_P0C,
            "expected": exp,
        }
    )

    if len(vectors) != D3S2_P0C_SLICE_COUNT:
        raise SystemExit("p0c slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P0C_KINDS:
        raise SystemExit(f"p0c kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode26_slice_vectors() -> List[Dict[str, Any]]:
    """Mode26 append-only slice (2 vectors) after the frozen 102-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) ES resume=1 + MANAGEMENT RESUME + true ANCHOR full success
    rows_a, named_a, _pvd_a = _mode26_material_rows(
        include_es=True, resume=1, discard=0
    )
    # Fail-closed independent parse of fixture carrier resume/discard.
    es_r, es_d = _parse_es_resume_discard(from_hex(named_a["es"]["value_hex"]))
    if es_r != 1 or es_d != 0:
        raise SystemExit(
            f"Mode26 success ES must declare resume=1 discard=0, got {es_r}/{es_d}"
        )
    calls_a, exp_a = run_d3s2_mode26_es_resume1_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK",
            "kind": "mode26_es_resume1_mgmt_resume_anchor_ok",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_ES_ID, D1_ML_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ES_ID,
                row=named_a["es"],
                expect_presence="PRESENT",
                note=(
                    "Mode26 carrier EVENT_SPOOL successful_resume_count=1 "
                    "discard_committed=0 (body fields patched; PVD→ANCHOR)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for MANAGEMENT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ML_ID,
                    row=named_a["mgmt"],
                    expect_presence="PRESENT",
                    note="MANAGEMENT RESUME (kind=15) secondary; PVD→ANCHOR",
                )
            ],
            "notes": (
                "Mode26 FOCUS stream + BIND_MANAGEMENT success: live "
                "EVENT_SPOOL declares successful_resume_count=1 + "
                "discard_committed=0, one MANAGEMENT RESUME row same-tx, "
                "true ANCHOR primary. Single READ_ONLY txn; baseline once; "
                "sequential zero-prefix reopen; SELECT carrier then FOCUS "
                "stream closes only on true iterator EXHAUSTED (H2; "
                "observed=1); empty SELECT then BIND proves ES carrier "
                "subject + ANCHOR PVD/raw; COMPLETE; mutation_calls=0. D1 "
                "authority rows patched via independent Python only."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_a,
        }
    )

    # B) MANAGEMENT + ANCHOR, ES absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode26_material_rows(
        include_es=False, resume=0, discard=0
    )
    calls_b, exp_b = run_d3s2_mode26_mgmt_without_es_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT",
            "kind": "mode26_mgmt_without_es_carrier_absent_corrupt",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_ML_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ML_ID,
                row=named_b["mgmt"],
                expect_presence="PRESENT",
                note="MANAGEMENT RESUME secondary without same-tx EVENT_SPOOL",
            ),
            "peer_ref": _d3s1.none_ref(
                "EVENT_SPOOL carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary get must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note=(
                        "true ANCHOR present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode26 empty-carrier SELECT (no EVENT_SPOOL) then "
                "BIND_MANAGEMENT on live MANAGEMENT RESUME: carrier "
                "companion exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary ANCHOR get "
                "must not proceed after carrier ABSENT. Not a Port failure "
                "path. abort; mutation_calls=0. Independent reference model "
                "— production C not used for expected."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE26_SLICE_COUNT:
        raise SystemExit("mode26 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE26_KINDS:
        raise SystemExit(f"mode26 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode24_slice_vectors() -> List[Dict[str, Any]]:
    """Mode24 append-only slice (2 vectors) after the frozen 104-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) RC reply_count=1 + RR RECEIPT + true DELIVERY full success
    rows_a, named_a, _pvd_a = _mode24_material_rows(
        include_rc=True, reply_count=1
    )
    rc_count, rc_draw, _rc_txn = _parse_rc_reply_count_and_delivery(
        from_hex(named_a["rc"]["value_hex"])
    )
    rr_kind, rr_draw, _rr_txn = _parse_rr_kind_and_delivery(
        from_hex(named_a["rr"]["value_hex"])
    )
    dlv_draw, _dlv_txn, _pid = _parse_delivery_raw_and_primary(
        from_hex(named_a["delivery"]["value_hex"])
    )
    if rc_count != 1 or rr_kind != RR_KIND_RECEIPT:
        raise SystemExit(
            f"Mode24 success must declare reply_count=1 RECEIPT, got "
            f"rc={rc_count} kind={rr_kind}"
        )
    if not (rc_draw == rr_draw == dlv_draw):
        raise SystemExit("Mode24 success delivery raw identity mismatch")
    calls_a, exp_a = run_d3s2_mode24_rc_reply1_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK",
            "kind": "mode24_rc_reply1_receipt_delivery_ok",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_RR_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note=(
                    "Mode24 carrier RESULT_CACHE reply_count=1 "
                    "(body field patched; PVD→DELIVERY VALUE_DIGEST)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_DLV_ID,
                row=named_a["delivery"],
                expect_presence="PRESENT",
                note="true primary DELIVERY for REVERSE_REPLY BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_RR_ID,
                    row=named_a["rr"],
                    expect_presence="PRESENT",
                    note="REVERSE_REPLY RECEIPT (kind=1) secondary; PVD→DELIVERY",
                )
            ],
            "notes": (
                "Mode24 FOCUS known-kind + BIND_REPLY success: live "
                "RESULT_CACHE declares reply_count=1, one REVERSE_REPLY "
                "RECEIPT (closed kind=1) same delivery raw, true DELIVERY "
                "primary. Single READ_ONLY txn; baseline once; sequential "
                "zero-prefix reopen; FOCUS known-kind exact_get matrix over "
                "closed kinds 1..4 (B6k; not iterator EXHAUSTED); count/"
                "popcount/mask close; empty SELECT then BIND proves "
                "RESULT_CACHE carrier subject + DELIVERY PVD/raw; COMPLETE; "
                "mutation_calls=0. D1 authority rows patched via independent "
                "Python only."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_a,
        }
    )

    # B) RR + DELIVERY, RC absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode24_material_rows(
        include_rc=False, reply_count=0
    )
    calls_b, exp_b = run_d3s2_mode24_rr_without_rc_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT",
            "kind": "mode24_rr_without_rc_carrier_absent_corrupt",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_RR_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RR_ID,
                row=named_b["rr"],
                expect_presence="PRESENT",
                note="REVERSE_REPLY RECEIPT secondary without same-tx RESULT_CACHE",
            ),
            "peer_ref": _d3s1.none_ref(
                "RESULT_CACHE carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary get must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_b["delivery"],
                    expect_presence="PRESENT",
                    note=(
                        "true DELIVERY present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode24 empty-carrier SELECT (no RESULT_CACHE) then "
                "BIND_REPLY on live REVERSE_REPLY RECEIPT: carrier companion "
                "exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary DELIVERY "
                "get must not proceed after carrier ABSENT. Not a Port "
                "failure path. abort; mutation_calls=0. Independent "
                "reference model — production C not used for expected."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE24_SLICE_COUNT:
        raise SystemExit("mode24 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE24_KINDS:
        raise SystemExit(f"mode24 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode23_slice_vectors() -> List[Dict[str, Any]]:
    """Mode23 append-only slice (2 vectors) after the frozen 106-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) STATE + ANCHOR + slots 0..L nontrivial equation full success
    rows_a, named_a, _pvd_a, L_a = _mode23_material_rows(
        include_state=True, nontrivial=True
    )
    if L_a != MODE23_ACCEPTED_L:
        raise SystemExit(f"Mode23 success L must be {MODE23_ACCEPTED_L}, got {L_a}")
    # Fail-closed independent parse of SUMMARY counters and RAW material.
    sum_ck, sum_cs, sum_slot, _own, valid, overflow, late_c, late_m = (
        _parse_tx_evidence_cell(from_hex(named_a["ev_slot0"]["value_hex"]))
    )
    if (
        sum_ck != EV_CELL_KIND_SUMMARY
        or sum_cs != EV_CELL_STATE_MATERIALIZED
        or sum_slot != 0
    ):
        raise SystemExit("Mode23 success SUMMARY shape pin fail")
    if (valid, overflow, late_c, late_m) != (2, 1, 1, 1):
        raise SystemExit(
            f"Mode23 success SUMMARY counters must be valid=2 overflow=1 "
            f"late=1 late_mat=1, got {valid}/{overflow}/{late_c}/{late_m}"
        )
    raw1_ck, raw1_cs, raw1_slot, _o1, _v1, _o1c, _l1, raw1_lm = (
        _parse_tx_evidence_cell(from_hex(named_a["ev_slot1"]["value_hex"]))
    )
    if (
        raw1_ck != EV_CELL_KIND_RAW
        or raw1_cs != EV_CELL_STATE_MATERIALIZED
        or raw1_slot != 1
        or raw1_lm != 1
    ):
        raise SystemExit("Mode23 success RAW slot1 MATERIALIZED late pin fail")
    # Equation + late coherence (docs/17 §18.13.12.1): valid == M + overflow
    # with M=1; observed_c=1 <= declared_c=1 <= declared_a=2; overflow <= valid.
    m_mat = 1
    if valid != m_mat + overflow:
        raise SystemExit("Mode23 success equation valid != M + overflow")
    if not (1 <= late_c <= valid and overflow <= valid):
        raise SystemExit("Mode23 success late/overflow coherence fail")
    calls_a, exp_a = run_d3s2_mode23_tx_state_slots_equation_success(
        binding, rows_a
    )
    vectors.append(
        {
            "id": "D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK",
            "kind": "mode23_tx_state_slots_L_equation_anchor_ok",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_EV_SUM_MAT_ID,
                D1_EV_RAW_MAT_ID,
                D1_EV_RAW_UNUSED_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_a["state"],
                expect_presence="PRESENT",
                note=(
                    "Mode23 carrier TRANSACTION_STATE retained "
                    "(D1 typed; same txn as EVIDENCE owner raw)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for EVIDENCE BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_EV_SUM_MAT_ID,
                    row=named_a["ev_slot0"],
                    expect_presence="PRESENT",
                    note=(
                        "SUMMARY@0 counters valid=2 overflow=1 late=1 "
                        "(body fields patched; PVD→ANCHOR)"
                    ),
                ),
                _d3s1.d1_ref_from_id(
                    D1_EV_RAW_MAT_ID,
                    row=named_a["ev_slot1"],
                    expect_presence="PRESENT",
                    note=(
                        "RAW MATERIALIZED slot1 late_material=1 (M=1); "
                        "PVD→ANCHOR"
                    ),
                ),
            ],
            "notes": (
                "Mode23 FOCUS known-slot + BIND_EVIDENCE success: retained "
                "TRANSACTION_STATE carrier, true ANCHOR primary, EVIDENCE "
                f"slots 0..L (accepted profile L={MODE23_ACCEPTED_L}) all "
                "PRESENT. SUMMARY@0 declares valid_material_count=2, "
                "raw_overflow_count=1, late_evidence_count=1; observed M=1 "
                "RAW MATERIALIZED (slot1 late_material=1) and slots 2..L "
                "RAW UNUSED so equation valid==M+overflow and late "
                "coherence hold without false late equality. Single "
                "READ_ONLY txn; baseline once; sequential zero-prefix "
                "reopen; FOCUS known-slot exact_get matrix 0..L (B6k); "
                "count bit2; BIND proves STATE carrier subject + ANCHOR "
                "PVD/raw for each EVIDENCE secondary; COMPLETE; "
                "mutation_calls=0. SHA256_COMPOSITE rows complete-key lex "
                "sorted. D1 authority rows patched via independent Python "
                "only."
            ),
            "ownership": OWNERSHIP_MODE23,
            "expected": exp_a,
        }
    )

    # B) EVIDENCE + ANCHOR, STATE absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b, _L_b = _mode23_material_rows(
        include_state=False, nontrivial=False
    )
    calls_b, exp_b = run_d3s2_mode23_evidence_without_state_corrupt(
        binding, rows_b
    )
    vectors.append(
        {
            "id": "D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT",
            "kind": "mode23_evidence_without_state_carrier_absent_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_EV_SUM_EMPTY_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_EV_SUM_EMPTY_ID,
                row=named_b["ev_slot0"],
                expect_presence="PRESENT",
                note=(
                    "EVIDENCE_CELL SUMMARY secondary without same-tx "
                    "TRANSACTION_STATE carrier"
                ),
            ),
            "peer_ref": _d3s1.none_ref(
                "TRANSACTION_STATE carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary get must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note=(
                        "true ANCHOR present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode23 empty-carrier SELECT (no TRANSACTION_STATE) then "
                "BIND_EVIDENCE on live EVIDENCE_CELL: carrier companion "
                "exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary ANCHOR "
                "get must not proceed after carrier ABSENT. Not a Port "
                "failure path. abort; mutation_calls=0. Independent "
                "reference model — production C not used for expected."
            ),
            "ownership": OWNERSHIP_MODE23,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE23_SLICE_COUNT:
        raise SystemExit("mode23 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE23_KINDS:
        raise SystemExit(f"mode23 kinds inventory mismatch: {kinds}")
    return vectors


# ---------------------------------------------------------------------------
# P1-B1 CLEANUP_PLAN matrix Modes22–23 only (§18.13.15 #5 / §18.13.8)
# Mode24–26 still-ordinary deferred to P1-B2 (explicit incomplete).
# ---------------------------------------------------------------------------


def _rebuild_cleanup_plan_key(subject_kind: int, primary_key_digest: bytes) -> bytes:
    """Independent CLEANUP_PLAN complete key (docs/17 §7.1 / §18.13.8)."""
    if len(primary_key_digest) != 32:
        raise SystemExit("CLEANUP_PLAN primary key digest must be 32")
    components = _d3s1.be16(int(subject_kind)) + bytes(primary_key_digest)
    return _d3s1.bkey(6, 0x63, 5, _d3s1.composite(0x63, components))


def _parse_cleanup_plan_subject(
    value: bytes,
) -> Tuple[int, int, bytes, bytes, bytes]:
    """Independent CLEANUP_PLAN parse.

    Returns (subject_kind, phase, subject_key_raw, subj_pkd, subj_pvd).
    """
    st, body, pvd = _d3s1.extract_envelope(value)
    if st != 0x63:
        raise SystemExit(f"CP parse: subtype {st:#x} != 0x63")
    if len(body) < 126:
        raise SystemExit(f"CP body too short: {len(body)}")
    subject_kind = struct.unpack_from(">H", body, 0)[0]
    phase = struct.unpack_from(">H", body, 2)[0]
    raw_len = struct.unpack_from(">H", body, 4)[0]
    if raw_len > 255 or 6 + raw_len + 120 > len(body):
        raise SystemExit(f"CP raw_len domain fail: {raw_len}")
    subject_raw = bytes(body[6 : 6 + raw_len])
    o = 6 + raw_len
    subj_pkd = bytes(body[o : o + 32])
    subj_pvd = bytes(body[o + 32 : o + 64])
    if pvd != subj_pvd:
        raise SystemExit("CP header PVD must equal body subject_primary_value_digest")
    return int(subject_kind), int(phase), subject_raw, subj_pkd, subj_pvd


def _mode22_cleanup_plan_ordinary_skip_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """DELIVERY + RESULT_CACHE(app=1) + matching DELIVERY CLEANUP_PLAN; no ATTEMPT.

    Ordinary declared A=1 with empty ATTEMPT band would undercount; plan PRESENT
    makes cleanup_skip=1. Independent D1 authority rows only.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    rc = cat[D1_RC_ID]
    cp = cat[D1_CP_DLV_ID]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    dlv_kd = _d3s1.key_digest(dlv_key)
    dlv_draw, dlv_txn, _pid = _parse_delivery_raw_and_primary(dlv_val)

    rc_key = from_hex(rc["key_hex"])
    rc_val = _d3s1.patch_pvd(from_hex(rc["value_hex"]), dlv_pvd)
    app_n, rc_draw, rc_txn = _parse_rc_app_attempt_and_delivery(rc_val)
    if app_n != 1:
        raise SystemExit(
            f"Mode22 cleanup-skip RC application_attempt_count must be 1, got {app_n}"
        )
    if rc_draw != dlv_draw or rc_txn != dlv_txn:
        raise SystemExit("Mode22 cleanup-skip RC/DELIVERY identity mismatch")
    if _d3s1.domain_value_framing(rc_val) != "current":
        raise SystemExit("Mode22 cleanup-skip RC framing not current")

    # Matching DELIVERY CLEANUP_PLAN (subject_kind=3 || KEY_DIGEST(DELIVERY)).
    cp_key = from_hex(cp["key_hex"])
    cp_val = from_hex(cp["value_hex"])
    sk, phase, _raw, subj_pkd, _subj_pvd = _parse_cleanup_plan_subject(cp_val)
    if sk != 3:
        raise SystemExit(f"Mode22 cleanup-skip CP subject_kind must be 3, got {sk}")
    if phase < 1:
        raise SystemExit("Mode22 cleanup-skip CP phase must be >=1")
    if subj_pkd != dlv_kd:
        raise SystemExit(
            "Mode22 cleanup-skip CP subject_primary_key_digest must equal "
            "KEY_DIGEST(complete DELIVERY key)"
        )
    rebuilt = _rebuild_cleanup_plan_key(3, dlv_kd)
    if rebuilt != cp_key:
        raise SystemExit("Mode22 cleanup-skip CLEANUP_PLAN key rebuild mismatch")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "rc": {"key_hex": hex_of(rc_key), "value_hex": hex_of(rc_val)},
        "cp": {"key_hex": hex_of(cp_key), "value_hex": hex_of(cp_val)},
    }
    domain_rows = [named["delivery"], named["rc"], named["cp"]]
    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x31:
            raise SystemExit("Mode22 cleanup-skip must not ship ATTEMPT")
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("Mode22 cleanup-skip must not ship AII")
    cp_n = sum(
        1
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if cp_n != 1:
        raise SystemExit(f"Mode22 cleanup-skip must ship exact 1 CLEANUP_PLAN, got {cp_n}")
    # Lex order pin among family-6 domain rows:
    # DELIVERY < RESULT_CACHE < CLEANUP_PLAN (complete-key).
    order = [
        from_hex(r["key_hex"])[9]
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10 and from_hex(r["key_hex"])[8] == 6
    ]
    if order != [0x40, 0x41, 0x63]:
        raise SystemExit(f"Mode22 cleanup-skip domain order pin fail: {order}")
    return all_rows, named, dlv_pvd


def run_d3s2_mode22_cleanup_plan_ordinary_skip_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22: RC app=1 + matching DLV CLEANUP_PLAN + empty ATTEMPT → COMPLETE.

    Independent reference model (docs/17 §18.13.8 / §18.13.15 case5):
      begin → baseline → SELECT RESULT_CACHE → CANCEL ABSENT + CLEANUP PRESENT
      (cleanup_skip=1) → checkpoint freezes cleanup_skip=1 / FOCUS_ATTEMPT /
      FOCUS_LIVE → FOCUS_ATTEMPT stream observed A=0 does not note undercount
      → empty SELECT → empty BIND_ATTEMPT → COMPLETE/adopt1. mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode22 cleanup-skip expects 20 rows (17+DLV+RC+CP), got {n_ok}"
        )
    rc_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    if len(rc_rows) != 1:
        raise SystemExit(
            f"mode22 cleanup-skip expects exact 1 RESULT_CACHE, got {len(rc_rows)}"
        )
    rc_key = from_hex(rc_rows[0]["key_hex"])
    rc_key_len = len(rc_key)
    if rc_key_len == 0 or rc_key_len > 45:
        raise SystemExit(f"RC carrier key_len invalid: {rc_key_len}")

    n_drive = 5
    n_open = 5
    walk = _walk_trace_segment(n_ok)

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT: profile + DLV + RC install + CANCEL + CLEANUP PRESENT + CP
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE carrier install
    port_trace.append("get")  # CANCEL_STATE ABSENT → B=0
    port_trace.append("get")  # CLEANUP_PLAN PRESENT → cleanup_skip=1
    port_trace.append("iter_next")  # CLEANUP_PLAN residual
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # FOCUS reopen is part of SELECT install coordination; modeled as next open
    port_trace.append("iter_open:prefix0")
    cp_trace_count = len(port_trace)
    # drive3 FOCUS_ATTEMPT stream (cleanup_skip ordinary A/B; empty secondary)
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND entry
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_ATTEMPT empty (no DELIVERY-owned ATTEMPT secondaries)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE
    port_trace.append("iter_next")  # CLEANUP_PLAN
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    # Checkpoint at end of drive2 (carrier installed, FOCUS reopened, skip=1).
    # Spy: begin open + SELECT open + FOCUS reopen = 3 opens;
    # baseline close + SELECT residual close = 2 closes; begin_calls=1.
    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "OK",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FOCUS_ATTEMPT,
        "cp_focus_live": 1,
        "cp_observed_a": 0,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 1,
        "cp_last_carrier_key_len": rc_key_len,
        "cp_last_carrier_key_hex": hex_of(rc_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 3,
        "cp_iter_close_calls": 2,
        "cp_trace_count": cp_trace_count,
    }
    if int(checkpoint_drive["cp_cleanup_skip"]) != 1:
        raise SystemExit("mode22 cleanup-skip checkpoint must freeze cleanup_skip=1")
    if int(checkpoint_drive["cp_phase"]) != PHASE_FOCUS_ATTEMPT:
        raise SystemExit("mode22 cleanup-skip checkpoint phase must be FOCUS_ATTEMPT")
    if (int(checkpoint_drive["cp_flags"]) & FLAG_COMPLETE_READY) != 0:
        raise SystemExit("mode22 cleanup-skip checkpoint must not set COMPLETE_READY")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,  # drive2 SELECT+setup+FOCUS reopen
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},  # FOCUS
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},  # SELECT empty
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},  # BIND
        {"op": "finalize", "expected_status": "OK"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode22 cleanup-skip drive count drift")
    if sum(1 for c in calls if int(c.get("has_checkpoint", 0)) == 1) != 1:
        raise SystemExit("mode22 cleanup-skip expects exactly one checkpoint")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # DELIVERY + RC + CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # SELECT setup 2 (CANCEL + CLEANUP PRESENT); BIND empty: 0 peer gets
        "d3_peer_get_count": 2,
        "d3_mode_applicable_count": 0,  # empty ATTEMPT BIND band
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_ATTEMPT,  # cleanup_skip still closes bit0
        "binding_complete_mask": MASK_ATTEMPT,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("mode22 cleanup-skip port_trace must be single-txn")
    # begin profile installs 17 family1-4 gets; SELECT adds CANCEL+CLEANUP.
    if port_trace.count("get") != 19:
        raise SystemExit(
            f"mode22 cleanup-skip must have 17 profile + 2 setup gets, "
            f"got {port_trace.count('get')}"
        )
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode22 cleanup-skip rows must be key-sorted")
    _ = binding
    return calls, expected


def _mode23_cleanup_plan_still_ordinary_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes, int
]:
    """ANCHOR + STATE + matching TX CLEANUP_PLAN; zero EVIDENCE cells.

    Plan is matching subject identity (not an unrelated residual row). Mode23
    forces cleanup_skip=0; known-slot presence matrix notes ABSENT slots.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    cp = cat[D1_CP_TX_ID]

    binding = _d3s1.default_binding_fields()
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(
            f"Mode23 still-ordinary L pin drift: binding L={L} != {MODE23_ACCEPTED_L}"
        )

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_kd = _d3s1.key_digest(anchor_key)

    state_key = from_hex(state["key_hex"])
    state_val = from_hex(state["value_hex"])

    cp_key = from_hex(cp["key_hex"])
    cp_val = from_hex(cp["value_hex"])
    sk, phase, subject_raw, subj_pkd, _subj_pvd = _parse_cleanup_plan_subject(cp_val)
    if sk != 2:
        raise SystemExit(
            f"Mode23 still-ordinary CP subject_kind must be 2 (TX), got {sk}"
        )
    if phase < 1:
        raise SystemExit("Mode23 still-ordinary CP phase must be >=1")
    if subj_pkd != anchor_kd:
        raise SystemExit(
            "Mode23 still-ordinary CP subject_primary_key_digest must equal "
            "KEY_DIGEST(complete ANCHOR key)"
        )
    rebuilt = _rebuild_cleanup_plan_key(2, anchor_kd)
    if rebuilt != cp_key:
        raise SystemExit("Mode23 still-ordinary CLEANUP_PLAN key rebuild mismatch")
    # subject_key_raw for TX is transaction ID (exact 16).
    if len(subject_raw) != 16:
        raise SystemExit(
            f"Mode23 still-ordinary CP TX subject_key_raw must be 16, got "
            f"{len(subject_raw)}"
        )

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        },
        "state": {
            "key_hex": hex_of(state_key),
            "value_hex": hex_of(state_val),
        },
        "cp": {"key_hex": hex_of(cp_key), "value_hex": hex_of(cp_val)},
    }
    domain_rows = [named["anchor"], named["state"], named["cp"]]
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    # Forbid any EVIDENCE cells (ordinary known-slot ABSENT path).
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x32:
            raise SystemExit("Mode23 still-ordinary must not ship EVIDENCE_CELL")
    cp_n = sum(
        1
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if cp_n != 1:
        raise SystemExit(
            f"Mode23 still-ordinary must ship exact 1 CLEANUP_PLAN, got {cp_n}"
        )
    _ = anchor_pvd
    return all_rows, named, anchor_pvd, L


def run_d3s2_mode23_cleanup_plan_still_ordinary_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]], L: int
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23: STATE + matching TX CLEANUP_PLAN + zero EVIDENCE → CORRUPT.

    Modes 23 force cleanup_skip=0 (no CLEANUP setup get). Known-slot matrix
    still requires slots 0..L PRESENT; all ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Checkpoint freezes cleanup_skip=0 on the failing drive.
    """
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"mode23 still-ordinary L pin fail: {L}")
    n_cells = L + 1
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode23 still-ordinary expects 20 rows (17+ANCHOR+STATE+CP), "
            f"got {n_ok}"
        )
    state_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    if len(state_rows) != 1:
        raise SystemExit(
            f"mode23 still-ordinary expects exact 1 STATE, got {len(state_rows)}"
        )
    state_key = from_hex(state_rows[0]["key_hex"])
    state_key_len = len(state_key)
    if state_key_len == 0 or state_key_len > 45:
        raise SystemExit(f"STATE carrier key_len invalid: {state_key_len}")

    n_drive = 2
    n_open = 2
    walk = _walk_trace_segment(n_ok)

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT residual + known-slot matrix (L+1 ABSENT gets) → CORRUPT
    # Mode23 forces cleanup_skip=0 without CLEANUP setup get.
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_cells)
    cp_trace_count = len(port_trace)
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "STORAGE_CORRUPT",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FAILED,
        "cp_focus_live": 1,
        "cp_observed_a": 0,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": state_key_len,
        "cp_last_carrier_key_hex": hex_of(state_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 2,
        "cp_iter_close_calls": 1,
        "cp_trace_count": cp_trace_count,
    }
    if int(checkpoint_drive["cp_cleanup_skip"]) != 0:
        raise SystemExit("mode23 still-ordinary checkpoint must freeze cleanup_skip=0")
    if int(checkpoint_drive["cp_phase"]) != PHASE_FAILED:
        raise SystemExit("mode23 still-ordinary checkpoint phase must be FAILED")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode23 still-ordinary drive count drift")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + STATE + CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # known-slot matrix L+1 ABSENT gets only (no CLEANUP setup get for M23)
        "d3_peer_get_count": n_cells,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("mode23 still-ordinary port_trace must be single-txn")
    # begin profile 17 + known-slot L+1 (no CLEANUP setup get for Mode23).
    if port_trace.count("get") != 17 + n_cells:
        raise SystemExit(
            f"mode23 still-ordinary must have 17 profile + {n_cells} slot gets, "
            f"got {port_trace.count('get')}"
        )
    _ = binding
    return calls, expected


def build_d3s2_p1b1_slice_vectors() -> List[Dict[str, Any]]:
    """P1-B1 append-only slice (2 vectors) after the frozen 128-prefix.

    Mode22 CLEANUP PRESENT ordinary-skip positive + Mode23 plan PRESENT
    still-ordinary negative. Mode24–26 deferred to P1-B2.
    """
    _assert_d1_authority_pin()
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) Mode22 ordinary-skip positive
    rows_a, named_a, _pvd_a = _mode22_cleanup_plan_ordinary_skip_material()
    app_n, rc_draw, _rc_txn = _parse_rc_app_attempt_and_delivery(
        from_hex(named_a["rc"]["value_hex"])
    )
    dlv_draw, _dlv_txn, _pid = _parse_delivery_raw_and_primary(
        from_hex(named_a["delivery"]["value_hex"])
    )
    if app_n != 1 or rc_draw != dlv_draw:
        raise SystemExit("P1-B1 Mode22 material identity self-check fail")
    calls_a, exp_a = run_d3s2_mode22_cleanup_plan_ordinary_skip_success(
        binding, rows_a
    )
    # Fail-closed structural pins before publish.
    cp_a = [c for c in calls_a if int(c.get("has_checkpoint", 0)) == 1]
    if len(cp_a) != 1 or int(cp_a[0]["cp_cleanup_skip"]) != 1:
        raise SystemExit("P1-B1 Mode22 expects checkpoint cleanup_skip=1")
    vectors.append(
        {
            "id": "D3S2_M22_CLEANUP_PLAN_PRESENT_ORDINARY_SKIP_OK",
            "kind": "mode22_cleanup_plan_present_ordinary_skip_ok",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_DLV_ID, D1_CP_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note=(
                    "Mode22 carrier RESULT_CACHE application_attempt_count=1 "
                    "(APPLICATION_FIRST); ordinary declared A>0 with empty "
                    "ATTEMPT band would undercount without cleanup_skip"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CP_DLV_ID,
                row=named_a["cp"],
                expect_presence="PRESENT",
                note=(
                    "matching DELIVERY CLEANUP_PLAN (subject_kind=3 || "
                    "KEY_DIGEST(complete DELIVERY key)); setup exact_get "
                    "PRESENT → cleanup_skip=1"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_a["delivery"],
                    expect_presence="PRESENT",
                    note="true primary DELIVERY subject of matching CLEANUP_PLAN",
                )
            ],
            "notes": (
                "P1-B1 formal (§18.13.15 case5 / §18.13.8 Mode22): live "
                "RESULT_CACHE declares application_attempt_count=1 with empty "
                "DELIVERY-owned ATTEMPT secondary band. Matching DELIVERY "
                "CLEANUP_PLAN PRESENT so SELECT setup sets cleanup_skip=1 and "
                "ordinary app undercount is not noted; empty BIND_ATTEMPT "
                "completes → COMPLETE/adopt1. Call-level checkpoint after "
                "SELECT setup freezes cleanup_skip=1 / FOCUS_ATTEMPT / "
                "FOCUS_LIVE / last_carrier=RC + spy begin/iter_open/iter_close/"
                "trace_count. Port-trace pins CANCEL ABSENT + CLEANUP PRESENT "
                "setup gets (d3_peer_get_count=2). Single READ_ONLY txn; "
                "mutation_calls=0; faults=[]. Independent D1 typed CLEANUP_PLAN "
                "builder (DSB3_CP_DLV_P1_TYPED) — not a metadata-only claim. "
                "Mode24–26 still-ordinary left for P1-B2."
            ),
            "ownership": OWNERSHIP_P1B1,
            "expected": exp_a,
        }
    )

    # B) Mode23 still-ordinary negative
    rows_b, named_b, _pvd_b, L = _mode23_cleanup_plan_still_ordinary_material()
    calls_b, exp_b = run_d3s2_mode23_cleanup_plan_still_ordinary_corrupt(
        binding, rows_b, L
    )
    cp_b = [c for c in calls_b if int(c.get("has_checkpoint", 0)) == 1]
    if len(cp_b) != 1 or int(cp_b[0]["cp_cleanup_skip"]) != 0:
        raise SystemExit("P1-B1 Mode23 expects checkpoint cleanup_skip=0")
    if exp_b.get("final_status") != "STORAGE_CORRUPT":
        raise SystemExit("P1-B1 Mode23 must be STORAGE_CORRUPT")
    vectors.append(
        {
            "id": "D3S2_M23_CLEANUP_PLAN_PRESENT_STILL_ORDINARY_CORRUPT",
            "kind": "mode23_cleanup_plan_present_still_ordinary_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_STATE_ID, D1_ANCHOR_ID, D1_CP_TX_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_b["state"],
                expect_presence="PRESENT",
                note=(
                    "Mode23 carrier TRANSACTION_STATE PRESENT; ordinary "
                    "known-slot EVIDENCE slots 0..L required PRESENT"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CP_TX_ID,
                row=named_b["cp"],
                expect_presence="PRESENT",
                note=(
                    "matching TX CLEANUP_PLAN (subject_kind=2 || "
                    "KEY_DIGEST(complete ANCHOR key)); Mode23 forces "
                    "cleanup_skip=0 (no ordinary skip)"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR subject of matching CLEANUP_PLAN",
                )
            ],
            "notes": (
                "P1-B1 formal (§18.13.15 case5 / §18.13.8 Modes23–26 still "
                "ordinary; Mode23 only this PR): matching TX CLEANUP_PLAN "
                "PRESENT on same snapshot as TRANSACTION_STATE carrier, but "
                "Mode23 forces cleanup_skip=0 and still applies ordinary "
                "known-slot EVIDENCE presence matrix. Zero EVIDENCE cells → "
                "slots 0..L ABSENT → note_terminal_corrupt STORAGE_CORRUPT "
                "(real failure path; not false skip / false success). Plan "
                "row is independent D1 typed CLEANUP_PLAN keyed by "
                "KEY_DIGEST(ANCHOR complete key) — not an unrelated residual. "
                "Call-level checkpoint on the CORRUPT drive freezes "
                "cleanup_skip=0 / phase FAILED / FOCUS_LIVE + spy counts. "
                "Port-trace pins L+1 known-slot gets and zero CLEANUP setup "
                "get (Mode23 gate early-return). Single READ_ONLY txn; "
                "mutation_calls=0; faults=[]. Mode24–26 deferred to P1-B2."
            ),
            "ownership": OWNERSHIP_P1B1,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_P1B1_SLICE_COUNT:
        raise SystemExit("p1b1 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1B1_KINDS:
        raise SystemExit(f"p1b1 kinds inventory mismatch: {kinds}")
    return vectors


# ---------------------------------------------------------------------------
# P1-B2 CLEANUP_PLAN still-ordinary Modes24–26 (§18.13.15 #5 residual /
# §18.13.8). Modes24–26 force cleanup_skip=0 without CLEANUP setup get.
# ---------------------------------------------------------------------------


def _mode24_cleanup_plan_still_ordinary_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """DELIVERY + RESULT_CACHE(reply_count=1) + matching DELIVERY CLEANUP_PLAN.

    Zero REVERSE_REPLY. Mode24 forces cleanup_skip=0; known-kind matrix notes
    ordinary reply undercount (declared A=1, observed A=0).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    rc = cat[D1_RC_ID]
    cp = cat[D1_CP_DLV_ID]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    dlv_kd = _d3s1.key_digest(dlv_key)
    dlv_draw, dlv_txn, _pid = _parse_delivery_raw_and_primary(dlv_val)

    rc_key = from_hex(rc["key_hex"])
    rc_val = _patch_rc_reply_count(from_hex(rc["value_hex"]), 1)
    rc_val = _d3s1.patch_pvd(rc_val, dlv_pvd)
    reply_n, rc_draw, rc_txn = _parse_rc_reply_count_and_delivery(rc_val)
    if reply_n != 1:
        raise SystemExit(
            f"Mode24 still-ordinary RC reply_count must be 1, got {reply_n}"
        )
    if rc_draw != dlv_draw or rc_txn != dlv_txn:
        raise SystemExit("Mode24 still-ordinary RC/DELIVERY identity mismatch")
    if _d3s1.domain_value_framing(rc_val) != "current":
        raise SystemExit("Mode24 still-ordinary RC framing not current")

    cp_key = from_hex(cp["key_hex"])
    cp_val = from_hex(cp["value_hex"])
    sk, phase, _raw, subj_pkd, _subj_pvd = _parse_cleanup_plan_subject(cp_val)
    if sk != 3:
        raise SystemExit(
            f"Mode24 still-ordinary CP subject_kind must be 3 (DLV), got {sk}"
        )
    if phase < 1:
        raise SystemExit("Mode24 still-ordinary CP phase must be >=1")
    if subj_pkd != dlv_kd:
        raise SystemExit(
            "Mode24 still-ordinary CP subject_primary_key_digest must equal "
            "KEY_DIGEST(complete DELIVERY key)"
        )
    rebuilt = _rebuild_cleanup_plan_key(3, dlv_kd)
    if rebuilt != cp_key:
        raise SystemExit("Mode24 still-ordinary CLEANUP_PLAN key rebuild mismatch")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "rc": {"key_hex": hex_of(rc_key), "value_hex": hex_of(rc_val)},
        "cp": {"key_hex": hex_of(cp_key), "value_hex": hex_of(cp_val)},
    }
    domain_rows = [named["delivery"], named["rc"], named["cp"]]
    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x42:
            raise SystemExit("Mode24 still-ordinary must not ship REVERSE_REPLY")
    cp_n = sum(
        1
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if cp_n != 1:
        raise SystemExit(
            f"Mode24 still-ordinary must ship exact 1 CLEANUP_PLAN, got {cp_n}"
        )
    order = [
        from_hex(r["key_hex"])[9]
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10 and from_hex(r["key_hex"])[8] == 6
    ]
    if order != [0x40, 0x41, 0x63]:
        raise SystemExit(f"Mode24 still-ordinary domain order pin fail: {order}")
    return all_rows, named, dlv_pvd


def run_d3s2_mode24_cleanup_plan_still_ordinary_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24: RC reply=1 + matching DLV CLEANUP_PLAN + zero RR → CORRUPT.

    Modes24 force cleanup_skip=0 (no CLEANUP setup get). Known-kind matrix
    (closed kinds 1..4) observes 0 vs declared reply_count=1 →
    note_terminal_corrupt STORAGE_CORRUPT. Checkpoint freezes cleanup_skip=0.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode24 still-ordinary expects 20 rows (17+DLV+RC+CP), got {n_ok}"
        )
    rc_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    if len(rc_rows) != 1:
        raise SystemExit(
            f"mode24 still-ordinary expects exact 1 RESULT_CACHE, got {len(rc_rows)}"
        )
    rc_key = from_hex(rc_rows[0]["key_hex"])
    rc_key_len = len(rc_key)
    if rc_key_len == 0 or rc_key_len > 45:
        raise SystemExit(f"RC carrier key_len invalid: {rc_key_len}")

    n_kinds = 4  # closed reply_kind 1..4
    n_drive = 2
    n_open = 2
    walk = _walk_trace_segment(n_ok)

    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT residual + known-kind matrix (4 ABSENT) → CORRUPT
    # Mode24 forces cleanup_skip=0 without CLEANUP setup get.
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_kinds)
    cp_trace_count = len(port_trace)
    port_trace.append("iter_close")
    port_trace.append("rollback")

    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "STORAGE_CORRUPT",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FAILED,
        "cp_focus_live": 1,
        "cp_observed_a": 0,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": rc_key_len,
        "cp_last_carrier_key_hex": hex_of(rc_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 2,
        "cp_iter_close_calls": 1,
        "cp_trace_count": cp_trace_count,
    }
    if int(checkpoint_drive["cp_cleanup_skip"]) != 0:
        raise SystemExit("mode24 still-ordinary checkpoint must freeze cleanup_skip=0")
    if int(checkpoint_drive["cp_phase"]) != PHASE_FAILED:
        raise SystemExit("mode24 still-ordinary checkpoint phase must be FAILED")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 24, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode24 still-ordinary drive count drift")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # DELIVERY + RC + CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": n_kinds,  # known-kind only; no CLEANUP setup get
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("mode24 still-ordinary port_trace must be single-txn")
    if port_trace.count("get") != 17 + n_kinds:
        raise SystemExit(
            f"mode24 still-ordinary must have 17 profile + {n_kinds} kind gets, "
            f"got {port_trace.count('get')}"
        )
    _ = binding
    return calls, expected


def _mode25_cleanup_plan_still_ordinary_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """ANCHOR + CUM(total=1) + matching TX CLEANUP_PLAN; zero RECENT.

    Mode25 forces cleanup_skip=0; known-slot matrix notes RECENT undercount
    (declared recent_n=1, observed RECENT=0) while CUM self is PRESENT.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    cum = cat[D1_CUM_ID]
    cp = cat[D1_CP_TX_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_kd = _d3s1.key_digest(anchor_key)

    cum_key = from_hex(cum["key_hex"])
    cum_val = _patch_cum_total_completed(from_hex(cum["value_hex"]), 1)
    cum_val = _d3s1.patch_pvd(cum_val, anchor_pvd)
    st_c, body_c, _ = _d3s1.extract_envelope(cum_val)
    if st_c != 0x51:
        raise SystemExit("Mode25 still-ordinary CUM subtype fail")
    total = struct.unpack_from(">Q", body_c, 20)[0]
    kind = struct.unpack_from(">H", body_c, 16)[0]
    slot = struct.unpack_from(">H", body_c, 18)[0]
    if total != 1 or kind != 1 or slot != 0:
        raise SystemExit(
            f"Mode25 still-ordinary CUM must be kind=1 slot=0 total=1, "
            f"got kind={kind} slot={slot} total={total}"
        )

    cp_key = from_hex(cp["key_hex"])
    cp_val = from_hex(cp["value_hex"])
    sk, phase, subject_raw, subj_pkd, _subj_pvd = _parse_cleanup_plan_subject(cp_val)
    if sk != 2:
        raise SystemExit(
            f"Mode25 still-ordinary CP subject_kind must be 2 (TX), got {sk}"
        )
    if phase < 1:
        raise SystemExit("Mode25 still-ordinary CP phase must be >=1")
    if subj_pkd != anchor_kd:
        raise SystemExit(
            "Mode25 still-ordinary CP subject_primary_key_digest must equal "
            "KEY_DIGEST(complete ANCHOR key)"
        )
    rebuilt = _rebuild_cleanup_plan_key(2, anchor_kd)
    if rebuilt != cp_key:
        raise SystemExit("Mode25 still-ordinary CLEANUP_PLAN key rebuild mismatch")
    if len(subject_raw) != 16:
        raise SystemExit(
            f"Mode25 still-ordinary CP TX subject_key_raw must be 16, got "
            f"{len(subject_raw)}"
        )

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        },
        "cum": {"key_hex": hex_of(cum_key), "value_hex": hex_of(cum_val)},
        "cp": {"key_hex": hex_of(cp_key), "value_hex": hex_of(cp_val)},
    }
    domain_rows = [named["anchor"], named["cum"], named["cp"]]
    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    # Forbid RECENT (kind=2) RETRY rows: only CUM (kind=1) allowed.
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x51:
            st_r, body_r, _ = _d3s1.extract_envelope(from_hex(r["value_hex"]))
            if st_r != 0x51:
                raise SystemExit("Mode25 still-ordinary RETRY subtype fail")
            rk = struct.unpack_from(">H", body_r, 16)[0]
            if rk == RS_KIND_RECENT:
                raise SystemExit("Mode25 still-ordinary must not ship RECENT")
    cp_n = sum(
        1
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if cp_n != 1:
        raise SystemExit(
            f"Mode25 still-ordinary must ship exact 1 CLEANUP_PLAN, got {cp_n}"
        )
    _ = anchor_pvd
    return all_rows, named, anchor_pvd


def run_d3s2_mode25_cleanup_plan_still_ordinary_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: CUM total=1 + matching TX CLEANUP_PLAN + zero RECENT → CORRUPT.

    Modes25 force cleanup_skip=0 (no CLEANUP setup get). Known-slot matrix
    (CUM + RECENT 0..3) observes RECENT=0 vs declared recent_n=1 →
    STORAGE_CORRUPT. Checkpoint freezes cleanup_skip=0 / observed_c=1 (CUM).
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode25 still-ordinary expects 20 rows (17+ANCHOR+CUM+CP), got {n_ok}"
        )
    cum_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x51
    ]
    if len(cum_rows) != 1:
        raise SystemExit(
            f"mode25 still-ordinary expects exact 1 RETRY CUM, got {len(cum_rows)}"
        )
    cum_key = from_hex(cum_rows[0]["key_hex"])
    cum_key_len = len(cum_key)
    if cum_key_len == 0 or cum_key_len > 45:
        raise SystemExit(f"CUM carrier key_len invalid: {cum_key_len}")

    n_slots = 5  # CUM + RECENT 0..3
    n_drive = 2
    n_open = 2
    walk = _walk_trace_segment(n_ok)

    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT residual + known-slot matrix → CORRUPT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_slots)
    cp_trace_count = len(port_trace)
    port_trace.append("iter_close")
    port_trace.append("rollback")

    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "STORAGE_CORRUPT",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FAILED,
        "cp_focus_live": 1,
        "cp_observed_a": 0,  # RECENT count
        "cp_observed_b": 0,
        "cp_observed_c": 1,  # CUM PRESENT
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": cum_key_len,
        "cp_last_carrier_key_hex": hex_of(cum_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 2,
        "cp_iter_close_calls": 1,
        "cp_trace_count": cp_trace_count,
    }
    if int(checkpoint_drive["cp_cleanup_skip"]) != 0:
        raise SystemExit("mode25 still-ordinary checkpoint must freeze cleanup_skip=0")
    if int(checkpoint_drive["cp_phase"]) != PHASE_FAILED:
        raise SystemExit("mode25 still-ordinary checkpoint phase must be FAILED")
    if int(checkpoint_drive["cp_observed_c"]) != 1:
        raise SystemExit("mode25 still-ordinary checkpoint must freeze CUM observed_c=1")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode25 still-ordinary drive count drift")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + CUM + CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": n_slots,  # known-slot only; no CLEANUP setup get
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("mode25 still-ordinary port_trace must be single-txn")
    if port_trace.count("get") != 17 + n_slots:
        raise SystemExit(
            f"mode25 still-ordinary must have 17 profile + {n_slots} slot gets, "
            f"got {port_trace.count('get')}"
        )
    _ = binding
    return calls, expected


def _mode26_cleanup_plan_still_ordinary_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """ANCHOR + EVENT_SPOOL(resume=1) + matching TX CLEANUP_PLAN; zero MGMT.

    Mode26 forces cleanup_skip=0; stream FOCUS notes MANAGEMENT undercount
    (declared A=resume+discard=1, observed A=0).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    es = cat[D1_ES_ID]
    cp = cat[D1_CP_TX_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_kd = _d3s1.key_digest(anchor_key)
    anchor_tx = anchor_key[13:29]
    if len(anchor_tx) != 16:
        raise SystemExit("Mode26 still-ordinary ANCHOR ID128 must be exact 16")

    es_key = from_hex(es["key_hex"])
    es_val = _patch_es_resume_discard(
        from_hex(es["value_hex"]), resume=1, discard=0
    )
    es_val = _d3s1.patch_pvd(es_val, anchor_pvd)
    got_r, got_d = _parse_es_resume_discard(es_val)
    if got_r != 1 or got_d != 0:
        raise SystemExit(
            f"Mode26 still-ordinary ES must be resume=1 discard=0, "
            f"got {got_r}/{got_d}"
        )
    es_tx = _d3s1.extract_envelope(es_val)[1][:16]
    if es_tx != anchor_tx:
        raise SystemExit("Mode26 still-ordinary EVENT_SPOOL tx must match ANCHOR")

    cp_key = from_hex(cp["key_hex"])
    cp_val = from_hex(cp["value_hex"])
    sk, phase, subject_raw, subj_pkd, _subj_pvd = _parse_cleanup_plan_subject(cp_val)
    if sk != 2:
        raise SystemExit(
            f"Mode26 still-ordinary CP subject_kind must be 2 (TX), got {sk}"
        )
    if phase < 1:
        raise SystemExit("Mode26 still-ordinary CP phase must be >=1")
    if subj_pkd != anchor_kd:
        raise SystemExit(
            "Mode26 still-ordinary CP subject_primary_key_digest must equal "
            "KEY_DIGEST(complete ANCHOR key)"
        )
    rebuilt = _rebuild_cleanup_plan_key(2, anchor_kd)
    if rebuilt != cp_key:
        raise SystemExit("Mode26 still-ordinary CLEANUP_PLAN key rebuild mismatch")
    if len(subject_raw) != 16:
        raise SystemExit(
            f"Mode26 still-ordinary CP TX subject_key_raw must be 16, got "
            f"{len(subject_raw)}"
        )

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        },
        "es": {"key_hex": hex_of(es_key), "value_hex": hex_of(es_val)},
        "cp": {"key_hex": hex_of(cp_key), "value_hex": hex_of(cp_val)},
    }
    domain_rows = [named["anchor"], named["es"], named["cp"]]
    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x52:
            raise SystemExit(
                "Mode26 still-ordinary must not ship MANAGEMENT_LEDGER"
            )
    cp_n = sum(
        1
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if cp_n != 1:
        raise SystemExit(
            f"Mode26 still-ordinary must ship exact 1 CLEANUP_PLAN, got {cp_n}"
        )
    order = [
        from_hex(r["key_hex"])[9]
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10 and from_hex(r["key_hex"])[8] == 6
    ]
    if order != [0x20, 0x50, 0x63]:
        raise SystemExit(f"Mode26 still-ordinary domain order pin fail: {order}")
    return all_rows, named, anchor_pvd


def run_d3s2_mode26_cleanup_plan_still_ordinary_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26: ES resume=1 + matching TX CLEANUP_PLAN + empty MGMT → CORRUPT.

    Modes26 force cleanup_skip=0 (no CLEANUP setup get). Stream FOCUS
    observes A=0 vs declared resume+discard=1 → STORAGE_CORRUPT.
    Checkpoint freezes cleanup_skip=0 on the failing FOCUS drive.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode26 still-ordinary expects 20 rows (17+ANCHOR+ES+CP), got {n_ok}"
        )
    es_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x50
    ]
    if len(es_rows) != 1:
        raise SystemExit(
            f"mode26 still-ordinary expects exact 1 EVENT_SPOOL, got {len(es_rows)}"
        )
    es_key = from_hex(es_rows[0]["key_hex"])
    es_key_len = len(es_key)
    if es_key_len == 0 or es_key_len > 45:
        raise SystemExit(f"ES carrier key_len invalid: {es_key_len}")

    n_drive = 3
    n_open = 3
    walk = _walk_trace_segment(n_ok)

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT residual (no Mode26 CLEANUP setup get) → reopen FOCUS
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 FOCUS_MANAGEMENT stream empty undercount → CORRUPT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    cp_trace_count = len(port_trace)
    port_trace.append("iter_close")
    port_trace.append("rollback")

    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "STORAGE_CORRUPT",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FAILED,
        "cp_focus_live": 1,
        "cp_observed_a": 0,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": es_key_len,
        "cp_last_carrier_key_hex": hex_of(es_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 3,
        "cp_iter_close_calls": 2,
        "cp_trace_count": cp_trace_count,
    }
    if int(checkpoint_drive["cp_cleanup_skip"]) != 0:
        raise SystemExit("mode26 still-ordinary checkpoint must freeze cleanup_skip=0")
    if int(checkpoint_drive["cp_phase"]) != PHASE_FAILED:
        raise SystemExit("mode26 still-ordinary checkpoint phase must be FAILED")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 26, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode26 still-ordinary drive count drift")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + ES + CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # stream FOCUS uses 0 exact_get; no CLEANUP setup get for Mode26
        "d3_peer_get_count": 0,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("mode26 still-ordinary port_trace must be single-txn")
    # begin profile 17 only (no CLEANUP setup get; stream 0 peer gets).
    if port_trace.count("get") != 17:
        raise SystemExit(
            f"mode26 still-ordinary must have 17 profile gets only "
            f"(no CLEANUP setup), got {port_trace.count('get')}"
        )
    _ = binding
    return calls, expected


def build_d3s2_p1b2_slice_vectors() -> List[Dict[str, Any]]:
    """P1-B2 append-only slice (3 vectors) after the frozen 130-prefix.

    Mode24/25/26 CLEANUP_PLAN PRESENT still-ordinary negatives (case5 residual).
    """
    _assert_d1_authority_pin()
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) Mode24 still-ordinary negative
    rows_a, named_a, _pvd_a = _mode24_cleanup_plan_still_ordinary_material()
    reply_n, rc_draw, _rc_txn = _parse_rc_reply_count_and_delivery(
        from_hex(named_a["rc"]["value_hex"])
    )
    dlv_draw, _dlv_txn, _pid = _parse_delivery_raw_and_primary(
        from_hex(named_a["delivery"]["value_hex"])
    )
    if reply_n != 1 or rc_draw != dlv_draw:
        raise SystemExit("P1-B2 Mode24 material identity self-check fail")
    calls_a, exp_a = run_d3s2_mode24_cleanup_plan_still_ordinary_corrupt(
        binding, rows_a
    )
    cp_a = [c for c in calls_a if int(c.get("has_checkpoint", 0)) == 1]
    if len(cp_a) != 1 or int(cp_a[0]["cp_cleanup_skip"]) != 0:
        raise SystemExit("P1-B2 Mode24 expects checkpoint cleanup_skip=0")
    if exp_a.get("final_status") != "STORAGE_CORRUPT":
        raise SystemExit("P1-B2 Mode24 must be STORAGE_CORRUPT")
    vectors.append(
        {
            "id": "D3S2_M24_CLEANUP_PLAN_PRESENT_STILL_ORDINARY_CORRUPT",
            "kind": "mode24_cleanup_plan_present_still_ordinary_corrupt",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_DLV_ID, D1_CP_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note=(
                    "Mode24 carrier RESULT_CACHE reply_count=1; ordinary "
                    "known-kind REVERSE_REPLY presence required"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CP_DLV_ID,
                row=named_a["cp"],
                expect_presence="PRESENT",
                note=(
                    "matching DELIVERY CLEANUP_PLAN (subject_kind=3 || "
                    "KEY_DIGEST(complete DELIVERY key)); Mode24 forces "
                    "cleanup_skip=0 (no ordinary skip; no CLEANUP setup get)"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_a["delivery"],
                    expect_presence="PRESENT",
                    note="true primary DELIVERY subject of matching CLEANUP_PLAN",
                )
            ],
            "notes": (
                "P1-B2 formal (§18.13.15 case5 residual / §18.13.8 Mode24): "
                "live RESULT_CACHE declares reply_count=1 with matching "
                "DELIVERY CLEANUP_PLAN PRESENT on same snapshot, but Mode24 "
                "forces cleanup_skip=0 and still applies ordinary known-kind "
                "REVERSE_REPLY presence matrix (closed kinds 1..4). Zero "
                "REVERSE_REPLY → observed A=0 != declared 1 → "
                "note_terminal_corrupt STORAGE_CORRUPT (real ordinary path; "
                "not false skip / false success). Plan row is independent D1 "
                "typed CLEANUP_PLAN keyed by KEY_DIGEST(DELIVERY complete "
                "key). Call-level checkpoint on the CORRUPT drive freezes "
                "cleanup_skip=0 / phase FAILED / FOCUS_LIVE + spy counts. "
                "Port-trace pins 4 known-kind gets and zero CLEANUP setup "
                "get. Single READ_ONLY txn; mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1B2,
            "expected": exp_a,
        }
    )

    # B) Mode25 still-ordinary negative
    rows_b, named_b, _pvd_b = _mode25_cleanup_plan_still_ordinary_material()
    calls_b, exp_b = run_d3s2_mode25_cleanup_plan_still_ordinary_corrupt(
        binding, rows_b
    )
    cp_b = [c for c in calls_b if int(c.get("has_checkpoint", 0)) == 1]
    if len(cp_b) != 1 or int(cp_b[0]["cp_cleanup_skip"]) != 0:
        raise SystemExit("P1-B2 Mode25 expects checkpoint cleanup_skip=0")
    if int(cp_b[0]["cp_observed_c"]) != 1:
        raise SystemExit("P1-B2 Mode25 expects checkpoint observed_c=1 (CUM)")
    if exp_b.get("final_status") != "STORAGE_CORRUPT":
        raise SystemExit("P1-B2 Mode25 must be STORAGE_CORRUPT")
    vectors.append(
        {
            "id": "D3S2_M25_CLEANUP_PLAN_PRESENT_STILL_ORDINARY_CORRUPT",
            "kind": "mode25_cleanup_plan_present_still_ordinary_corrupt",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_CUM_ID, D1_ANCHOR_ID, D1_CP_TX_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named_b["cum"],
                expect_presence="PRESENT",
                note=(
                    "Mode25 carrier RETRY CUM total_completed_cycle_count=1; "
                    "ordinary RECENT slot presence required (recent_n=1)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CP_TX_ID,
                row=named_b["cp"],
                expect_presence="PRESENT",
                note=(
                    "matching TX CLEANUP_PLAN (subject_kind=2 || "
                    "KEY_DIGEST(complete ANCHOR key)); Mode25 forces "
                    "cleanup_skip=0 (no ordinary skip; no CLEANUP setup get)"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR subject of matching CLEANUP_PLAN",
                )
            ],
            "notes": (
                "P1-B2 formal (§18.13.15 case5 residual / §18.13.8 Mode25): "
                "retained CUM total=1 with matching TX CLEANUP_PLAN PRESENT "
                "on same snapshot, but Mode25 forces cleanup_skip=0 and still "
                "applies ordinary known-slot RECENT presence matrix. Zero "
                "RECENT while declared recent_n=1 → STORAGE_CORRUPT (CUM "
                "self PRESENT so observed_c=1; RECENT observed_a=0). Plan "
                "row is independent D1 typed CLEANUP_PLAN keyed by "
                "KEY_DIGEST(ANCHOR complete key). Checkpoint freezes "
                "cleanup_skip=0 / phase FAILED / FOCUS_LIVE / observed_c=1. "
                "Port-trace pins 5 known-slot gets (CUM+RECENT0..3) and zero "
                "CLEANUP setup get. Single READ_ONLY txn; mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P1B2,
            "expected": exp_b,
        }
    )

    # C) Mode26 still-ordinary negative
    rows_c, named_c, _pvd_c = _mode26_cleanup_plan_still_ordinary_material()
    resume_c, discard_c = _parse_es_resume_discard(
        from_hex(named_c["es"]["value_hex"])
    )
    if resume_c + discard_c != 1:
        raise SystemExit("P1-B2 Mode26 ES declared total must be 1")
    calls_c, exp_c = run_d3s2_mode26_cleanup_plan_still_ordinary_corrupt(
        binding, rows_c
    )
    cp_c = [c for c in calls_c if int(c.get("has_checkpoint", 0)) == 1]
    if len(cp_c) != 1 or int(cp_c[0]["cp_cleanup_skip"]) != 0:
        raise SystemExit("P1-B2 Mode26 expects checkpoint cleanup_skip=0")
    if exp_c.get("final_status") != "STORAGE_CORRUPT":
        raise SystemExit("P1-B2 Mode26 must be STORAGE_CORRUPT")
    vectors.append(
        {
            "id": "D3S2_M26_CLEANUP_PLAN_PRESENT_STILL_ORDINARY_CORRUPT",
            "kind": "mode26_cleanup_plan_present_still_ordinary_corrupt",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_c),
            "alt_rows": {},
            "faults": [],
            "calls": calls_c,
            "d1_refs": [D1_ES_ID, D1_ANCHOR_ID, D1_CP_TX_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ES_ID,
                row=named_c["es"],
                expect_presence="PRESENT",
                note=(
                    "Mode26 carrier EVENT_SPOOL resume=1 discard=0 "
                    "(declared A=1); ordinary MANAGEMENT stream required"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CP_TX_ID,
                row=named_c["cp"],
                expect_presence="PRESENT",
                note=(
                    "matching TX CLEANUP_PLAN (subject_kind=2 || "
                    "KEY_DIGEST(complete ANCHOR key)); Mode26 forces "
                    "cleanup_skip=0 (no ordinary skip; no CLEANUP setup get)"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_c["anchor"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR subject of matching CLEANUP_PLAN",
                )
            ],
            "notes": (
                "P1-B2 formal (§18.13.15 case5 residual / §18.13.8 Mode26): "
                "live EVENT_SPOOL declares resume+discard=1 with matching TX "
                "CLEANUP_PLAN PRESENT on same snapshot (carrier/true-primary "
                "subject), but Mode26 forces cleanup_skip=0 and still applies "
                "ordinary MANAGEMENT stream cardinality. Empty MANAGEMENT "
                "secondary band → observed A=0 != declared 1 → stream "
                "undercount STORAGE_CORRUPT. Plan row is independent D1 typed "
                "CLEANUP_PLAN keyed by KEY_DIGEST(ANCHOR complete key). "
                "Checkpoint freezes cleanup_skip=0 / phase FAILED / "
                "FOCUS_LIVE. Port-trace pins zero CLEANUP setup get and zero "
                "stream peer gets (d3_peer_get_count=0). Single READ_ONLY "
                "txn; mutation_calls=0; faults=[]. Case5 Mode21 existing + "
                "22/23 P1-B1 + 24–26 this slice aligned; D3-S2 complete not "
                "claimed."
            ),
            "ownership": OWNERSHIP_P1B2,
            "expected": exp_c,
        }
    )

    if len(vectors) != D3S2_P1B2_SLICE_COUNT:
        raise SystemExit("p1b2 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1B2_KINDS:
        raise SystemExit(f"p1b2 kinds inventory mismatch: {kinds}")
    return vectors



# ---------------------------------------------------------------------------
# P1-C1 Mode23 illegal slot + equation/late fails
# (docs/17 §18.13.12.1 / §18.13.15 cases 3,19)
# ---------------------------------------------------------------------------


def _mode23_p1c1_base_domain(
    *,
    summary_valid: int,
    summary_overflow: int,
    summary_late: int,
    summary_late_mat: int,
    raw1_state: int,
    raw1_late_mat: int,
    extra_slot_L_plus_1: bool,
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes, int]:
    """STATE + ANCHOR + EVIDENCE slots for P1-C1 Mode23 formal vectors.

    All single-record cells are D1 typed-valid. Cross-row equation/late/
    illegal-slot judgments are D3-S2 only (not D1 invalid).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    sum_mat = cat[D1_EV_SUM_MAT_ID]
    sum_empty = cat[D1_EV_SUM_EMPTY_ID]
    raw_unused = cat[D1_EV_RAW_UNUSED_ID]
    raw_mat = cat[D1_EV_RAW_MAT_ID]
    binding = _d3s1.default_binding_fields()
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(
            f"P1-C1 Mode23 L pin drift: binding L={L} != {MODE23_ACCEPTED_L}"
        )
    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        },
        "state": {
            "key_hex": hex_of(from_hex(state["key_hex"])),
            "value_hex": hex_of(from_hex(state["value_hex"])),
        },
    }
    domain_rows: List[Dict[str, str]] = [named["anchor"], named["state"]]

    sum_tmpl = (
        from_hex(sum_empty["value_hex"])
        if int(summary_valid) == 0
        else from_hex(sum_mat["value_hex"])
    )
    k0, v0 = _build_tx_evidence_value(
        template_value=sum_tmpl,
        slot=0,
        cell_kind=EV_CELL_KIND_SUMMARY,
        cell_state=EV_CELL_STATE_MATERIALIZED,
        valid=int(summary_valid),
        overflow=int(summary_overflow),
        late_count=int(summary_late),
        late_material=int(summary_late_mat),
        anchor_pvd=anchor_pvd,
    )
    named["ev_slot0"] = {"key_hex": hex_of(k0), "value_hex": hex_of(v0)}
    domain_rows.append(named["ev_slot0"])

    if int(raw1_state) == EV_CELL_STATE_MATERIALIZED:
        k1, v1 = _build_tx_evidence_value(
            template_value=from_hex(raw_mat["value_hex"]),
            slot=1,
            cell_kind=EV_CELL_KIND_RAW,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            late_material=int(raw1_late_mat),
            anchor_pvd=anchor_pvd,
        )
    else:
        k1, v1 = _build_tx_evidence_value(
            template_value=from_hex(raw_unused["value_hex"]),
            slot=1,
            cell_kind=EV_CELL_KIND_RAW,
            cell_state=EV_CELL_STATE_UNUSED,
            late_material=0,
            anchor_pvd=anchor_pvd,
        )
    named["ev_slot1"] = {"key_hex": hex_of(k1), "value_hex": hex_of(v1)}
    domain_rows.append(named["ev_slot1"])

    for slot in range(2, L + 1):
        ks, vs = _build_tx_evidence_value(
            template_value=from_hex(raw_unused["value_hex"]),
            slot=slot,
            cell_kind=EV_CELL_KIND_RAW,
            cell_state=EV_CELL_STATE_UNUSED,
            late_material=0,
            anchor_pvd=anchor_pvd,
        )
        name = f"ev_slot{slot}"
        named[name] = {"key_hex": hex_of(ks), "value_hex": hex_of(vs)}
        domain_rows.append(named[name])

    if extra_slot_L_plus_1:
        k_x, v_x = _build_tx_evidence_value(
            template_value=from_hex(raw_unused["value_hex"]),
            slot=L + 1,
            cell_kind=EV_CELL_KIND_RAW,
            cell_state=EV_CELL_STATE_UNUSED,
            late_material=0,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot_L_plus_1"] = {
            "key_hex": hex_of(k_x),
            "value_hex": hex_of(v_x),
        }
        domain_rows.append(named["ev_slot_L_plus_1"])
        # D1 allows slot<=8; L+1 with L=3 is typed-valid (not D1 corrupt).
        if L + 1 > 8:
            raise SystemExit("P1-C1 illegal slot must stay D1-typed-valid (<=8)")

    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd, L


def _mode23_evidence_lex_slots(named: Dict[str, Dict[str, str]]) -> List[int]:
    """Return EVIDENCE slot_index values in complete-key lex order."""
    items: List[Tuple[bytes, int]] = []
    for name, row in named.items():
        if not name.startswith("ev_slot"):
            continue
        key = from_hex(row["key_hex"])
        _ck, _cs, slot, *_rest = _parse_tx_evidence_cell(
            from_hex(row["value_hex"])
        )
        items.append((key, int(slot)))
    items.sort(key=lambda t: t[0])
    return [s for _k, s in items]


def run_d3s2_mode23_illegal_slot_L_plus_1_corrupt(
    binding: Dict[str, Any],
    rows: List[Dict[str, str]],
    named: Dict[str, Dict[str, str]],
    L: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23: slots 0..L coherent + extra L+1 → FOCUS green, BIND CORRUPT."""
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"illegal-slot L pin fail: {L}")
    n_required = L + 1
    n_cells = n_required + 1  # + illegal L+1
    n_ok = len(rows)
    if n_ok != 17 + 2 + n_cells:
        raise SystemExit(
            f"illegal-slot expects {17 + 2 + n_cells} rows, got {n_ok}"
        )
    lex_slots = _mode23_evidence_lex_slots(named)
    if sorted(lex_slots) != list(range(0, L + 2)):
        raise SystemExit(f"illegal-slot lex slot set drift: {lex_slots}")
    # BIND walks lex order; note on first slot > L without peer gets after.
    legal_before_illegal = 0
    for s in lex_slots:
        if s > L:
            break
        legal_before_illegal += 1
    if legal_before_illegal != n_required:
        # With current TX owner keys slot L+1 is last; pin that shape.
        raise SystemExit(
            f"illegal-slot expected all {n_required} legal before illegal in "
            f"lex order, got {legal_before_illegal} (lex={lex_slots})"
        )

    n_drive = 4
    n_open = 4
    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS known-slot 0..L only (B6k; not L+1)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_required)
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND: legal secondaries STATE+ANCHOR; illegal carrier get then note
    # (slot authority after carrier body; before true primary; max 2 gets/row)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    for s in lex_slots:
        port_trace.append("iter_next")  # EVIDENCE
        if s <= L:
            port_trace.append("get")  # STATE carrier
            port_trace.append("get")  # ANCHOR primary
        else:
            # illegal slot: carrier exact_get then note before primary get
            port_trace.append("get")  # STATE carrier
            break
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for di in range(n_drive):
        if di < n_drive - 1:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
        else:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    bind_peer_gets = legal_before_illegal * 2 + 1  # +1 carrier get on illegal
    d3_peer = n_required + bind_peer_gets
    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2 + n_cells,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": d3_peer,
        "d3_mode_applicable_count": legal_before_illegal + 1,  # illegal visited
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_EVIDENCE,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("illegal-slot port_trace must be single-txn")
    if port_trace.count("get") != 17 + d3_peer:
        raise SystemExit(
            f"illegal-slot get budget: expect 17+{d3_peer}, "
            f"got {port_trace.count('get')}"
        )
    return calls, expected


def run_d3s2_mode23_focus_equation_or_late_corrupt(
    binding: Dict[str, Any],
    rows: List[Dict[str, str]],
    L: int,
    *,
    kind_tag: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23 FOCUS known-slot close CORRUPT (equation or late). No BIND."""
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"{kind_tag} L pin fail: {L}")
    n_cells = L + 1
    n_ok = len(rows)
    if n_ok != 17 + 2 + n_cells:
        raise SystemExit(
            f"{kind_tag} expects {17 + 2 + n_cells} rows, got {n_ok}"
        )
    n_drive = 2
    n_open = 2
    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_cells)
    port_trace.append("iter_close")
    port_trace.append("rollback")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]
    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2 + n_cells,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": n_cells,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit(f"{kind_tag} port_trace must be single-txn")
    if port_trace.count("get") != 17 + n_cells:
        raise SystemExit(
            f"{kind_tag} get budget fail: got {port_trace.count('get')}"
        )
    return calls, expected



def _mode23_p1c1_cancel_multi_domain(
    *,
    include_tx_evidence: bool,
    include_cancel_ev: bool,
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], int]:
    """CANCEL_FIRST / multi-owner Mode23 domain material (D1 fixtures only).

    Complete-key lex order of existing fixtures:
      ANCHOR < STATE < TX EVIDENCE slots < EV_DLV < DELIVERY < RC CANCEL
    ⇒ CANCEL RESULT is last Mode23 carrier vs TX STATE (declared_L scratch 0
    after last FOCUS). TX EVIDENCE keys sort before EV_DLV so BIND proves
    legal TX secondaries before CANCEL slot0 finding.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    sum_empty = cat[D1_EV_SUM_EMPTY_ID]
    raw_unused = cat[D1_EV_RAW_UNUSED_ID]
    ev_dlv = cat[D1_EV_DLV_SUM_EMPTY_ID]
    dlv = cat[D1_DLV_APP_DS_ID]
    rc = cat[D1_RC_CANCEL_FIRST_ID]
    binding = _d3s1.default_binding_fields()
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"cancel/multi L pin fail: {L}")
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(from_hex(anchor["key_hex"])),
            "value_hex": hex_of(anchor_val),
        },
        "state": {
            "key_hex": hex_of(from_hex(state["key_hex"])),
            "value_hex": hex_of(from_hex(state["value_hex"])),
        },
        "dlv": {
            "key_hex": hex_of(from_hex(dlv["key_hex"])),
            "value_hex": hex_of(dlv_val),
        },
        "rc_cancel": {
            "key_hex": hex_of(from_hex(rc["key_hex"])),
            "value_hex": hex_of(from_hex(rc["value_hex"])),
        },
    }
    # Fail-closed carrier order pin before assembly.
    if not (from_hex(named["state"]["key_hex"]) < from_hex(named["rc_cancel"]["key_hex"])):
        raise SystemExit("STATE must sort before RC CANCEL (fixture order)")
    app, _dlv_raw, _txn = _parse_rc_app_attempt_and_delivery(
        from_hex(named["rc_cancel"]["value_hex"])
    )
    if app != 0:
        raise SystemExit("RC CANCEL_FIRST must have application_attempt_count=0")

    domain_rows: List[Dict[str, str]] = []
    if include_tx_evidence:
        domain_rows.extend([named["anchor"], named["state"]])
        k0, v0 = _build_tx_evidence_value(
            template_value=from_hex(sum_empty["value_hex"]),
            slot=0,
            cell_kind=EV_CELL_KIND_SUMMARY,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            valid=0,
            overflow=0,
            late_count=0,
            late_material=0,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot0"] = {"key_hex": hex_of(k0), "value_hex": hex_of(v0)}
        domain_rows.append(named["ev_slot0"])
        for slot in range(1, L + 1):
            ks, vs = _build_tx_evidence_value(
                template_value=from_hex(raw_unused["value_hex"]),
                slot=slot,
                cell_kind=EV_CELL_KIND_RAW,
                cell_state=EV_CELL_STATE_UNUSED,
                late_material=0,
                anchor_pvd=anchor_pvd,
            )
            nm = f"ev_slot{slot}"
            named[nm] = {"key_hex": hex_of(ks), "value_hex": hex_of(vs)}
            domain_rows.append(named[nm])
    if include_cancel_ev:
        patched = _d3s1.patch_pvd(from_hex(ev_dlv["value_hex"]), dlv_pvd)
        if _d3s1.header_pvd(patched) != dlv_pvd:
            raise SystemExit("EV_DLV PVD patch fail")
        named["ev_dlv"] = {
            "key_hex": hex_of(from_hex(ev_dlv["key_hex"])),
            "value_hex": hex_of(patched),
        }
        domain_rows.append(named["ev_dlv"])
        if include_tx_evidence:
            for slot in range(0, L + 1):
                if not (
                    from_hex(named[f"ev_slot{slot}"]["key_hex"])
                    < from_hex(named["ev_dlv"]["key_hex"])
                ):
                    raise SystemExit(
                        f"TX ev_slot{slot} must sort before EV_DLV"
                    )
    domain_rows.append(named["dlv"])
    domain_rows.append(named["rc_cancel"])
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, L


def run_d3s2_mode23_cancel_first_slot0_corrupt(
    binding: Dict[str, Any],
    rows: List[Dict[str, str]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """CANCEL_FIRST empty set + EV slot0 → FOCUS green, BIND CORRUPT (1 get)."""
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"cancel-slot0 L pin fail: {L}")
    n_ok = len(rows)
    # 17 profile + EV_DLV + DELIVERY + RC = 20
    if n_ok != 17 + 3:
        raise SystemExit(f"cancel-slot0 expects 20 rows, got {n_ok}")
    n_drive = 4
    n_open = 4
    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # baseline
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT+FOCUS CANCEL empty (no known-slot gets)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT empty → BIND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # BIND: profile + EV; carrier get then note (no primary)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # EV_DLV
    port_trace.append("get")  # RC carrier
    port_trace.append("iter_close")
    port_trace.append("rollback")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for di in range(n_drive):
        if di < n_drive - 1:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
        else:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    d3_peer = 1  # only illegal row carrier get
    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": d3_peer,
        "d3_mode_applicable_count": 1,
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_EVIDENCE,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("cancel-slot0 must be single-txn")
    if port_trace.count("get") != 17 + d3_peer:
        raise SystemExit(
            f"cancel-slot0 get budget: expect 17+{d3_peer}, got "
            f"{port_trace.count('get')}"
        )
    return calls, expected


def run_d3s2_mode23_multi_owner_cancel_last_tx_ok(
    binding: Dict[str, Any],
    rows: List[Dict[str, str]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """TX legal 0..L + CANCEL empty; CANCEL last FOCUS; COMPLETE."""
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"multi-ok L pin fail: {L}")
    n_cells = L + 1
    n_ok = len(rows)
    # 17 + ANCHOR+STATE + EV×(L+1) + DLV + RC = 17+2+4+2 = 25
    if n_ok != 17 + 2 + n_cells + 2:
        raise SystemExit(f"multi-ok expects {17+2+n_cells+2} rows, got {n_ok}")
    n_drive = 5
    n_open = 5
    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # STATE FOCUS known-slot
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_cells)
    port_trace.append("iter_close")
    # CANCEL FOCUS empty
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT empty → BIND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # BIND TX secondaries only
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    for _ in range(n_cells):
        port_trace.append("iter_next")
        port_trace.append("get")  # STATE carrier
        port_trace.append("get")  # ANCHOR primary
    port_trace.append("iter_next")  # DLV
    port_trace.append("iter_next")  # RC
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    port_trace.append("rollback")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    bind_gets = n_cells * 2
    d3_peer = n_cells + bind_gets
    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2 + n_cells + 2,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": d3_peer,
        "d3_mode_applicable_count": n_cells,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_EVIDENCE,
        "binding_complete_mask": MASK_EVIDENCE,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if port_trace.count("get") != 17 + d3_peer:
        raise SystemExit(
            f"multi-ok get budget: expect 17+{d3_peer}, got "
            f"{port_trace.count('get')}"
        )
    return calls, expected


def run_d3s2_mode23_multi_owner_tx_before_cancel_ev_corrupt(
    binding: Dict[str, Any],
    rows: List[Dict[str, str]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """TX legal + CANCEL slot0; TX EV keys before EV_DLV; BIND CORRUPT."""
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"multi-corrupt L pin fail: {L}")
    n_cells = L + 1
    n_ok = len(rows)
    # + EV_DLV
    if n_ok != 17 + 2 + n_cells + 3:
        raise SystemExit(
            f"multi-corrupt expects {17+2+n_cells+3} rows, got {n_ok}"
        )
    n_drive = 5
    n_open = 5
    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_cells)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # BIND: legal TX then EV_DLV carrier get → note
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    for _ in range(n_cells):
        port_trace.append("iter_next")
        port_trace.append("get")
        port_trace.append("get")
    port_trace.append("iter_next")  # EV_DLV
    port_trace.append("get")  # RC carrier then note
    port_trace.append("iter_close")
    port_trace.append("rollback")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for di in range(n_drive):
        if di < n_drive - 1:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
        else:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    bind_gets = n_cells * 2 + 1
    d3_peer = n_cells + bind_gets
    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2 + n_cells + 3,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": d3_peer,
        "d3_mode_applicable_count": n_cells + 1,
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_EVIDENCE,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    if port_trace.count("get") != 17 + d3_peer:
        raise SystemExit(
            f"multi-corrupt get budget: expect 17+{d3_peer}, got "
            f"{port_trace.count('get')}"
        )
    return calls, expected



def build_d3s2_p1c1_slice_vectors() -> List[Dict[str, Any]]:
    """P1-C1 append-only slice (3 vectors) after the frozen 133-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # ---- (1) illegal slot L+1 after FOCUS green ----
    rows_a, named_a, _pvd_a, L_a = _mode23_p1c1_base_domain(
        summary_valid=0,
        summary_overflow=0,
        summary_late=0,
        summary_late_mat=0,
        raw1_state=EV_CELL_STATE_UNUSED,
        raw1_late_mat=0,
        extra_slot_L_plus_1=True,
    )
    # Equation coherent on 0..L: valid=0, M=0, overflow=0.
    s0 = _parse_tx_evidence_cell(from_hex(named_a["ev_slot0"]["value_hex"]))
    if (s0[0], s0[1], s0[2], s0[4], s0[5], s0[6]) != (
        EV_CELL_KIND_SUMMARY,
        EV_CELL_STATE_MATERIALIZED,
        0,
        0,
        0,
        0,
    ):
        raise SystemExit("P1-C1 illegal SUMMARY shape pin fail")
    x = _parse_tx_evidence_cell(
        from_hex(named_a["ev_slot_L_plus_1"]["value_hex"])
    )
    if x[0] != EV_CELL_KIND_RAW or x[2] != L_a + 1 or x[2] > 8:
        raise SystemExit("P1-C1 illegal L+1 must be D1-typed RAW slot<=8")
    calls_a, exp_a = run_d3s2_mode23_illegal_slot_L_plus_1_corrupt(
        binding, rows_a, named_a, L_a
    )
    vectors.append(
        {
            "id": "D3S2_M23_ILLEGAL_SLOT_L_PLUS_1_BIND_CORRUPT",
            "kind": "mode23_illegal_slot_L_plus_1_bind_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_EV_SUM_EMPTY_ID,
                D1_EV_RAW_UNUSED_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_a["state"],
                expect_presence="PRESENT",
                note="Mode23 retained TRANSACTION_STATE carrier",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for legal BIND rows before illegal",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_EV_RAW_UNUSED_ID,
                    row=named_a["ev_slot_L_plus_1"],
                    expect_presence="PRESENT",
                    note=(
                        f"extra RAW UNUSED slot L+1={L_a + 1} D1-typed-valid "
                        f"(slot<=8) same owner/PVD; S2 BIND illegal vs L={L_a}"
                    ),
                )
            ],
            "notes": (
                "P1-C1 formal (§18.13.15 case3 / §18.13.12.1 Mode23): all "
                f"required slots 0..L (L={MODE23_ACCEPTED_L}) PRESENT with "
                "empty SUMMARY equation-green (valid=M=overflow=0), plus "
                "extra RAW slot L+1 D1-typed-valid (slot<=8) same owner/PVD. "
                "FOCUS known-slot matrix exact_get 0..L only → count bit2 "
                "green; BIND_EVIDENCE walks lex-ordered secondaries, notes "
                "illegal slot > accepted profile L via note_terminal_corrupt "
                "STORAGE_CORRUPT after carrier get and before primary get on "
                "that row. Not mere D1 "
                "invalid; not Port failure; not carrier/primary absence. "
                "Single READ_ONLY txn; mutation_calls=0. Independent Python "
                "only. Not D3-S2 complete claim."
            ),
            "ownership": OWNERSHIP_P1C1,
            "expected": exp_a,
        }
    )

    # ---- (2) equation fail ----
    rows_b, named_b, _pvd_b, L_b = _mode23_p1c1_base_domain(
        summary_valid=2,
        summary_overflow=0,
        summary_late=0,
        summary_late_mat=0,
        raw1_state=EV_CELL_STATE_MATERIALIZED,
        raw1_late_mat=0,
        extra_slot_L_plus_1=False,
    )
    sb = _parse_tx_evidence_cell(from_hex(named_b["ev_slot0"]["value_hex"]))
    rb = _parse_tx_evidence_cell(from_hex(named_b["ev_slot1"]["value_hex"]))
    if (sb[4], sb[5], sb[6], sb[7]) != (2, 0, 0, 0):
        raise SystemExit(f"equation-fail SUMMARY counters pin fail: {sb}")
    if rb[1] != EV_CELL_STATE_MATERIALIZED or rb[7] != 0:
        raise SystemExit("equation-fail RAW1 must be MATERIALIZED late=0")
    # D1: overflow<=valid, late<=valid; S2 equation 2 != 1+0
    if not (sb[5] <= sb[4] and sb[6] <= sb[4]):
        raise SystemExit("equation-fail must remain D1 counter-domain valid")
    if sb[4] == 1 + sb[5]:
        raise SystemExit("equation-fail must violate valid == M + overflow")
    calls_b, exp_b = run_d3s2_mode23_focus_equation_or_late_corrupt(
        binding, rows_b, L_b, kind_tag="equation-fail"
    )
    vectors.append(
        {
            "id": "D3S2_M23_EQUATION_FAIL_VALID_NE_M_PLUS_OVERFLOW_CORRUPT",
            "kind": "mode23_equation_fail_valid_ne_m_plus_overflow_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_EV_SUM_MAT_ID,
                D1_EV_RAW_MAT_ID,
                D1_EV_RAW_UNUSED_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_b["state"],
                expect_presence="PRESENT",
                note="Mode23 retained TRANSACTION_STATE carrier",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_b["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR present (FOCUS path only)",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_EV_SUM_MAT_ID,
                    row=named_b["ev_slot0"],
                    expect_presence="PRESENT",
                    note=(
                        "SUMMARY@0 valid=2 overflow=0 late=0 (D1 domain OK); "
                        "equation 2 != M=1 + overflow=0"
                    ),
                ),
                _d3s1.d1_ref_from_id(
                    D1_EV_RAW_MAT_ID,
                    row=named_b["ev_slot1"],
                    expect_presence="PRESENT",
                    note="RAW MATERIALIZED slot1 (M=1) late_material=0",
                ),
            ],
            "notes": (
                "P1-C1 formal (§18.13.15 case19 / §18.13.12.1 Mode23 equation): "
                "all slots 0..L PRESENT with matching STATE+ANCHOR. SUMMARY "
                "counters D1-valid (overflow<=valid, late<=valid, "
                "late_mat==(late>0)) but valid_material_count=2 != M=1 + "
                "raw_overflow_count=0 → FOCUS known-slot close "
                "note_terminal_corrupt STORAGE_CORRUPT. BIND must not run. "
                "Not absence/carrier/BIND failure; not Port path. Single "
                "READ_ONLY txn; mutation_calls=0. Independent Python only."
            ),
            "ownership": OWNERSHIP_P1C1,
            "expected": exp_b,
        }
    )

    # ---- (3) late coherence fail (constructible under D1) ----
    rows_c, named_c, _pvd_c, L_c = _mode23_p1c1_base_domain(
        summary_valid=1,
        summary_overflow=0,
        summary_late=0,
        summary_late_mat=0,
        raw1_state=EV_CELL_STATE_MATERIALIZED,
        raw1_late_mat=1,
        extra_slot_L_plus_1=False,
    )
    sc = _parse_tx_evidence_cell(from_hex(named_c["ev_slot0"]["value_hex"]))
    rc = _parse_tx_evidence_cell(from_hex(named_c["ev_slot1"]["value_hex"]))
    if (sc[4], sc[5], sc[6], sc[7]) != (1, 0, 0, 0):
        raise SystemExit(f"late-fail SUMMARY pin fail: {sc}")
    if rc[1] != EV_CELL_STATE_MATERIALIZED or rc[7] != 1:
        raise SystemExit("late-fail RAW1 must be MATERIALIZED late_material=1")
    # Equation green: 1 == 1 + 0; late: observed_c=1 > declared_c=0
    if sc[4] != 1 + sc[5]:
        raise SystemExit("late-fail must keep equation green")
    if not (1 > sc[6]):
        raise SystemExit("late-fail must have observed_c > declared_c")
    # D1 SUMMARY late_mat == (late_count > 0) holds with both 0.
    if int(sc[7]) != (1 if int(sc[6]) > 0 else 0):
        raise SystemExit("late-fail SUMMARY must remain D1 late_mat coherent")
    calls_c, exp_c = run_d3s2_mode23_focus_equation_or_late_corrupt(
        binding, rows_c, L_c, kind_tag="late-fail"
    )
    vectors.append(
        {
            "id": "D3S2_M23_LATE_COHERENCE_OBSERVED_GT_DECLARED_CORRUPT",
            "kind": "mode23_late_coherence_observed_gt_declared_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_c),
            "alt_rows": {},
            "faults": [],
            "calls": calls_c,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_EV_SUM_MAT_ID,
                D1_EV_RAW_MAT_ID,
                D1_EV_RAW_UNUSED_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_c["state"],
                expect_presence="PRESENT",
                note="Mode23 retained TRANSACTION_STATE carrier",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_c["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR present (FOCUS path only)",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_EV_SUM_MAT_ID,
                    row=named_c["ev_slot0"],
                    expect_presence="PRESENT",
                    note=(
                        "SUMMARY@0 valid=1 overflow=0 late_evidence_count=0 "
                        "late_material=0 (D1 same-record OK)"
                    ),
                ),
                _d3s1.d1_ref_from_id(
                    D1_EV_RAW_MAT_ID,
                    row=named_c["ev_slot1"],
                    expect_presence="PRESENT",
                    note=(
                        "RAW MATERIALIZED late_material=1 → observed_c=1; "
                        "equation valid==M+overflow still green"
                    ),
                ),
            ],
            "notes": (
                "P1-C1 formal (§18.13.15 case19 / §18.13.12.1 Mode23 late): "
                "all slots 0..L PRESENT, equation green (valid=1 == M=1 + "
                "overflow=0), at least one RAW MATERIALIZED late_material=1 "
                "while SUMMARY late_evidence_count=0 (SUMMARY late_material=0 "
                "keeps D1 late_mat==(late>0)). observed_c > declared_c → "
                "FOCUS close STORAGE_CORRUPT. Normative forbids requiring "
                "declared_c==observed_c (overflow late may lack RAW). "
                "Constructible under D1; not absence/carrier/BIND fail. "
                "Single READ_ONLY txn; mutation_calls=0. Independent Python."
            ),
            "ownership": OWNERSHIP_P1C1,
            "expected": exp_c,
        }
    )


    # ---- (4) CANCEL_FIRST + slot0 Evidence CORRUPT ----
    rows_d, named_d, L_d = _mode23_p1c1_cancel_multi_domain(
        include_tx_evidence=False, include_cancel_ev=True
    )
    calls_d, exp_d = run_d3s2_mode23_cancel_first_slot0_corrupt(binding, rows_d)
    vectors.append(
        {
            "id": "D3S2_M23_CANCEL_FIRST_SLOT0_BIND_CORRUPT",
            "kind": "mode23_cancel_first_slot0_bind_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_d),
            "alt_rows": {},
            "faults": [],
            "calls": calls_d,
            "d1_refs": [
                D1_RC_CANCEL_FIRST_ID,
                D1_DLV_APP_DS_ID,
                D1_EV_DLV_SUM_EMPTY_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_CANCEL_FIRST_ID,
                row=named_d["rc_cancel"],
                expect_presence="PRESENT",
                note="CANCEL_FIRST RESULT_CACHE carrier (app_attempt=0)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_DLV_APP_DS_ID,
                row=named_d["dlv"],
                expect_presence="PRESENT",
                note="true primary DELIVERY for EV_DLV PVD",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_EV_DLV_SUM_EMPTY_ID,
                    row=named_d["ev_dlv"],
                    expect_presence="PRESENT",
                    note="any Evidence under CANCEL_FIRST is S2 illegal",
                )
            ],
            "notes": (
                "P1-C1 formal: DELIVERY CANCEL_FIRST RESULT expects exact 0 "
                "EVIDENCE cells. Slot0 SUMMARY for that owner is D1-typed-valid "
                "and slot0<=profile L, but BIND_EVIDENCE notes STORAGE_CORRUPT "
                "from carrier body shape after carrier exact_get and before "
                "true primary get (max 2 gets; this row consumes 1). "
                "Profile-only L authority would false-accept. mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P1C1,
            "expected": exp_d,
        }
    )

    # ---- (5) multi-owner CANCEL last FOCUS + TX legal COMPLETE ----
    rows_e, named_e, L_e = _mode23_p1c1_cancel_multi_domain(
        include_tx_evidence=True, include_cancel_ev=False
    )
    # Pin carrier order STATE < RC (CANCEL last FOCUS → declared_L=0).
    if not (
        from_hex(named_e["state"]["key_hex"])
        < from_hex(named_e["rc_cancel"]["key_hex"])
    ):
        raise SystemExit("multi-ok carrier order pin fail")
    calls_e, exp_e = run_d3s2_mode23_multi_owner_cancel_last_tx_ok(
        binding, rows_e
    )
    vectors.append(
        {
            "id": "D3S2_M23_MULTI_OWNER_CANCEL_LAST_TX_OK",
            "kind": "mode23_multi_owner_cancel_last_tx_ok",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_e),
            "alt_rows": {},
            "faults": [],
            "calls": calls_e,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_RC_CANCEL_FIRST_ID,
                D1_DLV_APP_DS_ID,
                D1_EV_SUM_EMPTY_ID,
                D1_EV_RAW_UNUSED_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_e["state"],
                expect_presence="PRESENT",
                note="TX retained STATE carrier (first FOCUS)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_RC_CANCEL_FIRST_ID,
                row=named_e["rc_cancel"],
                expect_presence="PRESENT",
                note="CANCEL_FIRST last FOCUS; declared_L scratch ends 0",
            ),
            "row_refs": [],
            "notes": (
                "P1-C1 formal anti last-declared_L: TX retained legal slots "
                f"0..L (L={MODE23_ACCEPTED_L}) coexist with CANCEL_FIRST empty "
                "evidence set. Fixture key order STATE < RC ⇒ CANCEL is last "
                "Mode23 carrier FOCUS and ctx.declared_L ends 0. BIND must use "
                "per-row carrier shape + profile L — not declared_L — so TX "
                "evidence COMPLETE green. mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P1C1,
            "expected": exp_e,
        }
    )

    # ---- (6) multi-owner TX before CANCEL EV CORRUPT ----
    rows_f, named_f, L_f = _mode23_p1c1_cancel_multi_domain(
        include_tx_evidence=True, include_cancel_ev=True
    )
    calls_f, exp_f = run_d3s2_mode23_multi_owner_tx_before_cancel_ev_corrupt(
        binding, rows_f
    )
    vectors.append(
        {
            "id": "D3S2_M23_MULTI_OWNER_TX_BEFORE_CANCEL_EV_CORRUPT",
            "kind": "mode23_multi_owner_tx_before_cancel_ev_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_f),
            "alt_rows": {},
            "faults": [],
            "calls": calls_f,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_RC_CANCEL_FIRST_ID,
                D1_DLV_APP_DS_ID,
                D1_EV_SUM_EMPTY_ID,
                D1_EV_RAW_UNUSED_ID,
                D1_EV_DLV_SUM_EMPTY_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_f["state"],
                expect_presence="PRESENT",
                note="TX STATE carrier (sorts before RC)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_EV_DLV_SUM_EMPTY_ID,
                row=named_f["ev_dlv"],
                expect_presence="PRESENT",
                note="CANCEL owner Evidence after TX EVIDENCE keys in lex order",
            ),
            "row_refs": [],
            "notes": (
                "P1-C1 formal: multi-owner TX legal 0..L + CANCEL_FIRST with "
                "slot0 Evidence. Computed fixture key order STATE < RC "
                "(CANCEL last FOCUS) and all TX EVIDENCE keys < EV_DLV so BIND "
                "walks legal TX secondaries first then notes CANCEL shape "
                "corrupt after carrier get. Profile-only L would false-accept "
                "slot0; last declared_L is 0 and is not authority. "
                "mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P1C1,
            "expected": exp_f,
        }
    )


    if len(vectors) != D3S2_P1C1_SLICE_COUNT:
        raise SystemExit("p1c1 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1C1_KINDS:
        raise SystemExit(f"p1c1 kinds inventory mismatch: {kinds}")
    return vectors


# ---------------------------------------------------------------------------
# P1-C2 Mode24/25 known-slot legality residual (§18.13.15 case3)
# Constructibility: D1 rejects reply_kind∉1..4 / CUM slot≠0 / RECENT slot>3
# so those are not S2 formal. Use D1-valid declared vs population shape fails.
# ---------------------------------------------------------------------------


def _reverse_reply_composite_key(reply_key_contents86: bytes) -> bytes:
    """Independent SHA256_COMPOSITE complete key for REVERSE_REPLY (0x42)."""
    if len(reply_key_contents86) != 86:
        raise SystemExit(
            f"RR composite reply_key contents must be exact 86, got "
            f"{len(reply_key_contents86)}"
        )
    return _d3s1.k_composite(0x42, _d3s1.raw16(reply_key_contents86))


def _rekey_rr_reply_kind(
    template_value: bytes, reply_kind: int, dlv_pvd: bytes
) -> Tuple[bytes, bytes]:
    """Rekey D1 REVERSE_REPLY to a closed reply_kind 1..4 + PVD→DELIVERY.

    Rewrites reply_key trailing u32 and body reply_kind field; rebuilds
    COMPOSITE key; CRC + PVD via stdlib only. Does not call production C.
    """
    if not (RR_KIND_MIN <= int(reply_kind) <= RR_KIND_MAX):
        raise SystemExit(
            f"RR rekey kind must stay in closed D1 domain 1..4, got {reply_kind}"
        )
    if len(dlv_pvd) != 32:
        raise SystemExit("RR rekey dlv_pvd must be exact 32")
    st, body, _ = _d3s1.extract_envelope(template_value)
    if st != 0x42 or len(body) != 330:
        raise SystemExit("RR rekey expects typed REVERSE_REPLY body 330")
    b = bytearray(body)
    # reply_key_raw contents trailing kind + body field kind bijection.
    struct.pack_into(">I", b, RR_REPLY_KIND_BODY_OFF, int(reply_kind))
    struct.pack_into(">I", b, RR_BODY_REPLY_KIND_FIELD_OFF, int(reply_kind))
    out = bytearray(template_value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("RR body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    val = _d3s1.patch_pvd(bytes(out), dlv_pvd)
    reply_contents = bytes(b[2 : 2 + 86])
    key = _reverse_reply_composite_key(reply_contents)
    got_kind, got_draw, _txn = _parse_rr_kind_and_delivery(val)
    if got_kind != int(reply_kind):
        raise SystemExit("RR rekey kind did not stick")
    # delivery raw identity unchanged.
    tpl_kind, tpl_draw, _ = _parse_rr_kind_and_delivery(template_value)
    if got_draw != tpl_draw:
        raise SystemExit("RR rekey must preserve delivery raw")
    _st2, _body2, pvd2 = _d3s1.extract_envelope(val)
    if pvd2 != dlv_pvd:
        raise SystemExit("RR rekey header PVD must equal DELIVERY VALUE_DIGEST")
    if _d3s1.domain_value_framing(val) != "current":
        raise SystemExit("RR rekey framing not current")
    _ = tpl_kind
    return key, val


def _rekey_recent_cycle(
    template_value: bytes,
    tx: bytes,
    *,
    cycle_id: int,
    anchor_pvd: bytes,
) -> Tuple[bytes, bytes]:
    """Rekey RECENT RETRY to cycle_id with D1 slot=(cycle-1) mod 4 + PVD.

    Independent body rewrite; preserves attempt/outcome fields from template
    except identity/cycle/slot. Does not call production C.
    """
    if len(tx) != 16 or len(anchor_pvd) != 32:
        raise SystemExit("RECENT rekey: tx=16 and anchor_pvd=32 required")
    if int(cycle_id) < 1:
        raise SystemExit(f"RECENT cycle_id must be >=1, got {cycle_id}")
    slot = (int(cycle_id) - 1) % 4
    st, body, _ = _d3s1.extract_envelope(template_value)
    if st != 0x51 or len(body) != 80:
        raise SystemExit("RECENT rekey expects typed RECENT body 80")
    b = bytearray(body)
    b[0:16] = tx
    struct.pack_into(">H", b, 16, RS_KIND_RECENT)
    struct.pack_into(">H", b, 18, int(slot))
    struct.pack_into(">Q", b, 20, int(cycle_id))
    out = bytearray(template_value)
    out[24:40] = tx  # primary_id
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("RECENT body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    val = _d3s1.patch_pvd(bytes(out), anchor_pvd)
    key = _retry_composite_key(tx, RS_KIND_RECENT, slot)
    got_tx, got_kind, got_slot = _parse_retry_tx_kind_slot(val)
    if got_tx != tx or got_kind != RS_KIND_RECENT or got_slot != int(slot):
        raise SystemExit("RECENT rekey identity did not stick")
    _st2, body2, pvd2 = _d3s1.extract_envelope(val)
    got_cycle = struct.unpack_from(">Q", body2, 20)[0]
    if got_cycle != int(cycle_id):
        raise SystemExit("RECENT rekey cycle did not stick")
    if pvd2 != anchor_pvd:
        raise SystemExit("RECENT header PVD must equal ANCHOR VALUE_DIGEST")
    # D1 slot arithmetic pin.
    if int(slot) != (int(cycle_id) - 1) % 4:
        raise SystemExit("RECENT slot vs cycle mod4 invariant fail")
    return key, val


def _mode24_p1c2_missing_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """DLV + RC reply_count=1; zero REVERSE_REPLY (declared>0 empty secondary)."""
    rows, named, dlv_pvd = _mode24_material_rows(include_rc=True, reply_count=1)
    # Drop RR secondary.
    rows = [
        r
        for r in rows
        if not (
            len(from_hex(r["key_hex"])) >= 10
            and from_hex(r["key_hex"])[8] == 6
            and from_hex(r["key_hex"])[9] == 0x42
        )
    ]
    named = {k: v for k, v in named.items() if k != "rr"}
    if "rr" in named:
        raise SystemExit("mode24 missing material still has RR")
    rr_n = sum(
        1
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x42
    )
    if rr_n != 0:
        raise SystemExit("mode24 missing material must ship zero RR")
    rc_n = sum(
        1
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    )
    if rc_n != 1:
        raise SystemExit("mode24 missing material expects exact 1 RC")
    rc_count, _, _ = _parse_rc_reply_count_and_delivery(
        from_hex(named["rc"]["value_hex"])
    )
    if rc_count != 1:
        raise SystemExit("mode24 missing RC reply_count must be 1")
    return rows, named, dlv_pvd


def _mode24_p1c2_extra_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """DLV + RC reply_count=1 + RECEIPT + DISPOSITION (undeclared extra kind)."""
    rows, named, dlv_pvd = _mode24_material_rows(include_rc=True, reply_count=1)
    # Base material already has RECEIPT; add DISPOSITION for same delivery.
    rr_disp_key, rr_disp_val = _rekey_rr_reply_kind(
        from_hex(named["rr"]["value_hex"]),
        RR_KIND_DISPOSITION,
        dlv_pvd,
    )
    named["rr_disposition"] = {
        "key_hex": hex_of(rr_disp_key),
        "value_hex": hex_of(rr_disp_val),
    }
    rows = sorted(
        list(rows) + [named["rr_disposition"]],
        key=lambda r: from_hex(r["key_hex"]),
    )
    kinds = []
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x42:
            kinds.append(_parse_rr_kind_and_delivery(from_hex(r["value_hex"]))[0])
    if sorted(kinds) != [RR_KIND_RECEIPT, RR_KIND_DISPOSITION]:
        raise SystemExit(f"mode24 extra expects kinds {{1,2}}, got {kinds}")
    rc_count, _, _ = _parse_rc_reply_count_and_delivery(
        from_hex(named["rc"]["value_hex"])
    )
    if rc_count != 1:
        raise SystemExit("mode24 extra RC reply_count must stay 1")
    return rows, named, dlv_pvd


def _mode25_p1c2_missing_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """ANCHOR + CUM total=1; zero RECENT (declared recent_n=1 empty)."""
    rows, named, anchor_pvd = _mode25_material_rows(
        include_cum=True, cum_total=1
    )
    filtered: List[Dict[str, str]] = []
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x51:
            _tx, kind, _slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
            if kind == RS_KIND_RECENT:
                continue
        filtered.append(r)
    rows = filtered
    named = {k: v for k, v in named.items() if k != "recent"}
    rec_n = 0
    cum_n = 0
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x51:
            continue
        _tx, kind, _slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if kind == RS_KIND_RECENT:
            rec_n += 1
        elif kind == RS_KIND_CUMULATIVE:
            cum_n += 1
    if rec_n != 0 or cum_n != 1:
        raise SystemExit(
            f"mode25 missing expects cum=1 recent=0, got cum={cum_n} rec={rec_n}"
        )
    return rows, named, anchor_pvd


def _mode25_p1c2_extra_material() -> Tuple[
    List[Dict[str, str]], Dict[str, Dict[str, str]], bytes
]:
    """ANCHOR + CUM total=1 + RECENT C1/slot0 + RECENT C2/slot1 (extra)."""
    rows, named, anchor_pvd = _mode25_material_rows(
        include_cum=True, cum_total=1
    )
    # Existing recent is C1/slot0; add C2/slot1 with D1 slot arithmetic.
    cat = _d1_catalog()
    rec_t = from_hex(cat[D1_REC_ID]["value_hex"])
    # TX from existing recent body.
    tx, kind0, slot0 = _parse_retry_tx_kind_slot(
        from_hex(named["recent"]["value_hex"])
    )
    if kind0 != RS_KIND_RECENT or slot0 != 0:
        raise SystemExit("mode25 extra base RECENT must be C1/slot0 template")
    rec2_key, rec2_val = _rekey_recent_cycle(
        rec_t, tx, cycle_id=2, anchor_pvd=anchor_pvd
    )
    named["recent_c2"] = {
        "key_hex": hex_of(rec2_key),
        "value_hex": hex_of(rec2_val),
    }
    rows = sorted(
        list(rows) + [named["recent_c2"]],
        key=lambda r: from_hex(r["key_hex"]),
    )
    rec_slots = []
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x51:
            continue
        _tx, kind, slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if kind == RS_KIND_RECENT:
            rec_slots.append(int(slot))
    if sorted(rec_slots) != [0, 1]:
        raise SystemExit(f"mode25 extra expects RECENT slots {{0,1}}, got {rec_slots}")
    return rows, named, anchor_pvd


def _run_d3s2_focus_known_slot_population_corrupt(
    *,
    mode: int,
    rows: List[Dict[str, str]],
    n_domain: int,
    n_matrix_gets: int,
    carrier_subtype: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Shared independent model: baseline + FOCUS matrix → CORRUPT; abort.

    Used for Mode24 known-kind (4 gets) and Mode25 known-slot (5 gets)
    declared vs observed population fails. No BIND; single RO txn.
    Mode24 carrier = RESULT_CACHE (0x41). Mode25 carrier = CUMULATIVE
    RETRY only (kind=1, slot=0) among possibly multiple 0x51 rows.
    """
    n_ok = len(rows)
    if n_ok != 17 + n_domain:
        raise SystemExit(
            f"mode{mode} population corrupt expects 17+{n_domain} rows, got {n_ok}"
        )
    carrier_rows: List[Dict[str, str]] = []
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != carrier_subtype:
            continue
        if mode == 25 and carrier_subtype == 0x51:
            _tx, kind, slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
            if kind != RS_KIND_CUMULATIVE or slot != 0:
                continue
        carrier_rows.append(r)
    if len(carrier_rows) != 1:
        raise SystemExit(
            f"mode{mode} population expects exact 1 carrier subtype "
            f"{carrier_subtype:#x}, got {len(carrier_rows)}"
        )
    carrier_key = from_hex(carrier_rows[0]["key_hex"])
    carrier_key_len = len(carrier_key)
    if carrier_key_len == 0 or carrier_key_len > 45:
        raise SystemExit(f"carrier key_len invalid: {carrier_key_len}")

    n_drive = 2
    n_open = 2
    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT residual + known-slot/kind matrix → CORRUPT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_matrix_gets)
    cp_trace_count = len(port_trace)
    port_trace.append("iter_close")
    port_trace.append("rollback")

    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "STORAGE_CORRUPT",
        "has_checkpoint": 1,
        "cp_phase": PHASE_FAILED,
        "cp_focus_live": 1,
        "cp_observed_a": 0 if mode == 24 and n_domain == 2 else -1,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": 0,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": carrier_key_len,
        "cp_last_carrier_key_hex": hex_of(carrier_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 2,
        "cp_iter_close_calls": 1,
        "cp_trace_count": cp_trace_count,
    }
    # observed_a is fixture-specific; drop -1 sentinel fields that bridge
    # does not require. Keep only fields other vectors use consistently.
    # For undercount Mode24 missing, observed_a=0; for overcount cases
    # observed is non-zero at fail — production notes before checkpoint
    # freezes observed after compare. Match still-ordinary: freeze 0 for
    # missing; for overcount freeze observed after matrix (2 for both extras).
    if mode == 24 and n_domain == 2:
        checkpoint_drive["cp_observed_a"] = 0  # missing RR
    elif mode == 24 and n_domain == 4:
        checkpoint_drive["cp_observed_a"] = 2  # RECEIPT+DISPOSITION
    elif mode == 25 and n_domain == 2:
        checkpoint_drive["cp_observed_a"] = 0  # missing RECENT
        checkpoint_drive["cp_observed_c"] = 1  # CUM present in matrix
    elif mode == 25 and n_domain == 4:
        checkpoint_drive["cp_observed_a"] = 2  # two RECENT
        checkpoint_drive["cp_observed_c"] = 1
    else:
        raise SystemExit(f"mode{mode} n_domain={n_domain} unexpected for p1c2")

    # Remove sentinel if any remaining
    if int(checkpoint_drive["cp_observed_a"]) < 0:
        raise SystemExit("checkpoint observed_a not set")

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": mode, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("population corrupt drive count drift")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": n_domain,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": n_matrix_gets,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("population corrupt port_trace must be single-txn")
    if port_trace.count("get") != 17 + n_matrix_gets:
        raise SystemExit(
            f"population corrupt get budget: expect 17+{n_matrix_gets}, "
            f"got {port_trace.count('get')}"
        )
    return calls, expected


def run_d3s2_mode24_reply_empty_secondary_undercount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24: RC reply_count=1 + zero RR → known-kind undercount CORRUPT."""
    _ = binding
    return _run_d3s2_focus_known_slot_population_corrupt(
        mode=24,
        rows=rows,
        n_domain=2,  # DLV + RC
        n_matrix_gets=4,
        carrier_subtype=0x41,
    )


def run_d3s2_mode24_reply_extra_disposition_overcount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24: RC reply_count=1 + RECEIPT+DISPOSITION → overcount CORRUPT."""
    _ = binding
    return _run_d3s2_focus_known_slot_population_corrupt(
        mode=24,
        rows=rows,
        n_domain=4,  # DLV + RC + RR×2
        n_matrix_gets=4,
        carrier_subtype=0x41,
    )


def run_d3s2_mode25_recent_missing_undercount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: CUM total=1 + zero RECENT → known-slot undercount CORRUPT."""
    _ = binding
    return _run_d3s2_focus_known_slot_population_corrupt(
        mode=25,
        rows=rows,
        n_domain=2,  # ANCHOR + CUM
        n_matrix_gets=5,
        carrier_subtype=0x51,
    )


def run_d3s2_mode25_recent_extra_slot_overcount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: CUM total=1 + RECENT slots 0+1 → overcount CORRUPT."""
    _ = binding
    return _run_d3s2_focus_known_slot_population_corrupt(
        mode=25,
        rows=rows,
        n_domain=4,  # ANCHOR + CUM + REC×2
        n_matrix_gets=5,
        carrier_subtype=0x51,
    )


def build_d3s2_p1c2_slice_vectors() -> List[Dict[str, Any]]:
    """P1-C2 append-only slice (4 vectors) after the frozen 139-prefix.

    Constructibility judgment (docs/17 §8.5–§8.6 D1 + §18.13.15 case3):
      * reply_kind∉1..4, CUM slot≠0, RECENT slot>3 → D1 same-record reject;
        not constructible as S2 formal rows under prior D1 invariants.
      * Substitutes: D1-valid declared reply_count / recent_n vs closed
        population under/over (missing or extra PRESENT kind/slot).
      * Production focus_close_compare already notes these; no false COMPLETE
        fix required (oracle + production bridge only).
    """
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # ---- (1) Mode24 reply_count=1 empty secondary undercount ----
    rows_a, named_a, _pvd_a = _mode24_p1c2_missing_material()
    calls_a, exp_a = run_d3s2_mode24_reply_empty_secondary_undercount_corrupt(
        binding, rows_a
    )
    vectors.append(
        {
            "id": "D3S2_M24_RC_REPLY1_EMPTY_SECONDARY_UNDERCOUNT_CORRUPT",
            "kind": "mode24_rc_reply1_empty_secondary_undercount_corrupt",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note="RESULT_CACHE reply_count=1 carrier; zero RR secondary",
            ),
            "peer_ref": _d3s1.none_ref(
                "known-kind matrix observes 0 PRESENT of closed kinds 1..4"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_a["delivery"],
                    expect_presence="PRESENT",
                    note="true primary DELIVERY present; FOCUS fails before BIND",
                )
            ],
            "notes": (
                "P1-C2 formal (§18.13.15 case3 / Mode24 known-kind): "
                "RESULT_CACHE declares reply_count=1 but closed reply_kind "
                "1..4 matrix finds zero REVERSE_REPLY → observed_a=0 != "
                "declared_a=1 → FOCUS B6k note_terminal_corrupt "
                "STORAGE_CORRUPT. Constructible D1-valid substitute for "
                "illegal reply_kind∉1..4 (D1-rejected; not fabricated). "
                "Not CLEANUP still-ordinary (no plan). Single READ_ONLY "
                "txn; Port-trace pins 4 known-kind gets; mutation_calls=0; "
                "independent Python expected."
            ),
            "ownership": OWNERSHIP_P1C2,
            "expected": exp_a,
        }
    )

    # ---- (2) Mode24 reply_count=1 + extra DISPOSITION overcount ----
    rows_b, named_b, _pvd_b = _mode24_p1c2_extra_material()
    calls_b, exp_b = run_d3s2_mode24_reply_extra_disposition_overcount_corrupt(
        binding, rows_b
    )
    vectors.append(
        {
            "id": "D3S2_M24_RC_REPLY1_EXTRA_DISPOSITION_OVERCOUNT_CORRUPT",
            "kind": "mode24_rc_reply1_extra_disposition_overcount_corrupt",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_RC_ID, D1_RR_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_b["rc"],
                expect_presence="PRESENT",
                note="RESULT_CACHE reply_count=1; population has 2 closed kinds",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_RR_ID,
                row=named_b["rr"],
                expect_presence="PRESENT",
                note="REVERSE_REPLY RECEIPT (kind=1) D1-valid",
            ),
            "row_refs": [
                {
                    "vector_id": D1_RR_ID,
                    "expect_presence": "PRESENT",
                    "key_hex": named_b["rr_disposition"]["key_hex"],
                    "value_hex": named_b["rr_disposition"]["value_hex"],
                    "note": (
                        "REVERSE_REPLY DISPOSITION (kind=2) rekeyed from "
                        "RECEIPT template; same delivery raw; D1 closed domain"
                    ),
                },
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_b["delivery"],
                    expect_presence="PRESENT",
                    note="true primary DELIVERY; FOCUS fails before BIND",
                ),
            ],
            "notes": (
                "P1-C2 formal (§18.13.15 case3 / Mode24 known-kind): "
                "RESULT_CACHE declares reply_count=1 but matrix finds "
                "RECEIPT+DISPOSITION (two closed kinds PRESENT) → "
                "observed_a=2 != declared_a=1 → FOCUS B6k "
                "STORAGE_CORRUPT (undeclared extra reply). Both RR rows "
                "D1-valid (kinds 1..4; delivery raw bijection). "
                "reply_kind∉1..4 not used (D1-rejected). Single READ_ONLY "
                "txn; 4 known-kind gets; mutation_calls=0; independent "
                "Python expected."
            ),
            "ownership": OWNERSHIP_P1C2,
            "expected": exp_b,
        }
    )

    # ---- (3) Mode25 CUM total=1 RECENT missing undercount ----
    rows_c, named_c, _pvd_c = _mode25_p1c2_missing_material()
    calls_c, exp_c = run_d3s2_mode25_recent_missing_undercount_corrupt(
        binding, rows_c
    )
    vectors.append(
        {
            "id": "D3S2_M25_CUM_TOTAL1_RECENT_MISSING_UNDERCOUNT_CORRUPT",
            "kind": "mode25_cum_total1_recent_missing_undercount_corrupt",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_c),
            "alt_rows": {},
            "faults": [],
            "calls": calls_c,
            "d1_refs": [D1_CUM_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named_c["cum"],
                expect_presence="PRESENT",
                note="CUM total=1 carrier; declared recent_n=min(1,4)=1; zero RECENT",
            ),
            "peer_ref": _d3s1.none_ref(
                "known-slot matrix RECENT 0..3 all ABSENT → observed_a=0"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_c["anchor"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR; FOCUS fails before BIND",
                )
            ],
            "notes": (
                "P1-C2 formal (§18.13.15 case3 / Mode25 known-slot): "
                "CUM total_completed_cycle_count=1 declares recent_n=1 but "
                "RECENT slots 0..3 all ABSENT → observed_a=0 != "
                "declared_b=1 → FOCUS B6k STORAGE_CORRUPT. Constructible "
                "D1-valid substitute for illegal RETRY slot "
                "(CUM slot≠0 / RECENT slot>3 are D1-rejected). Not CLEANUP "
                "still-ordinary (no plan). Single READ_ONLY txn; 5 known-"
                "slot gets (CUM+RECENT0..3); mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P1C2,
            "expected": exp_c,
        }
    )

    # ---- (4) Mode25 CUM total=1 + extra RECENT slot overcount ----
    rows_d, named_d, _pvd_d = _mode25_p1c2_extra_material()
    calls_d, exp_d = run_d3s2_mode25_recent_extra_slot_overcount_corrupt(
        binding, rows_d
    )
    vectors.append(
        {
            "id": "D3S2_M25_CUM_TOTAL1_RECENT_EXTRA_SLOT_OVERCOUNT_CORRUPT",
            "kind": "mode25_cum_total1_recent_extra_slot_overcount_corrupt",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_d),
            "alt_rows": {},
            "faults": [],
            "calls": calls_d,
            "d1_refs": [D1_CUM_ID, D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named_d["cum"],
                expect_presence="PRESENT",
                note="CUM total=1 carrier; declared recent_n=1; population has 2 RECENT",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_REC_ID,
                row=named_d["recent"],
                expect_presence="PRESENT",
                note="RECENT cycle1/slot0 D1-valid ((1-1) mod 4 = 0)",
            ),
            "row_refs": [
                {
                    "vector_id": D1_REC_ID,
                    "expect_presence": "PRESENT",
                    "key_hex": named_d["recent_c2"]["key_hex"],
                    "value_hex": named_d["recent_c2"]["value_hex"],
                    "note": (
                        "RECENT cycle2/slot1 D1-valid ((2-1) mod 4 = 1); "
                        "extra vs total=1 recent_n"
                    ),
                },
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_d["anchor"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR; FOCUS fails before BIND",
                ),
            ],
            "notes": (
                "P1-C2 formal (§18.13.15 case3 / Mode25 known-slot): "
                "CUM total=1 declares recent_n=1 but D1-valid RECENT "
                "population has cycle1/slot0 + cycle2/slot1 (both obey "
                "slot=(cycle-1)mod4 body arithmetic) → observed_a=2 != "
                "declared_b=1 → FOCUS B6k STORAGE_CORRUPT. Extra/missing "
                "population is the constructible substitute for D1-illegal "
                "RETRY slots. Close predicates compare count only (not a "
                "distinct cycle-set membership law). Single READ_ONLY txn; "
                "5 known-slot gets; mutation_calls=0; independent Python."
            ),
            "ownership": OWNERSHIP_P1C2,
            "expected": exp_d,
        }
    )

    if len(vectors) != D3S2_P1C2_SLICE_COUNT:
        raise SystemExit("p1c2 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1C2_KINDS:
        raise SystemExit(f"p1c2 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_suffix_vectors() -> List[Dict[str, Any]]:
    vectors = (
        build_d3s2_smoke_vectors()
        + build_d3s2_mode25_slice_vectors()
        + build_d3s2_mode26_slice_vectors()
        + build_d3s2_mode24_slice_vectors()
        + build_d3s2_mode23_slice_vectors()
        + build_d3s2_mode22_slice_vectors()
        + build_d3s2_mode21_slice_vectors()
        + build_d3s2_p0a_slice_vectors()
        + build_d3s2_p0b_slice_vectors()
        + build_d3s2_p0c_slice_vectors()
        + build_d3s2_p0d_slice_vectors()
        + build_d3s2_p1a_slice_vectors()
        + build_d3s2_p1d_slice_vectors()
        + build_d3s2_p1d2_slice_vectors()
        + build_d3s2_p1b1_slice_vectors()
        + build_d3s2_p1b2_slice_vectors()
        + build_d3s2_p1c1_slice_vectors()
        + build_d3s2_p1c2_slice_vectors()
    )
    if len(vectors) != D3S2_SUFFIX_COUNT:
        raise SystemExit("suffix count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_REQUIRED_KINDS:
        raise SystemExit(f"suffix kinds inventory mismatch: {kinds}")
    return vectors


def freeze_d3s1_prefix() -> Dict[str, Any]:
    """Rebuild the frozen 94-vector D3-S1 document via the independent generator."""
    doc = _d3s1.build_document()
    if doc.get("format") != D3S1_FORMAT:
        raise SystemExit(f"d3s1 format drift: {doc.get('format')}")
    if int(doc.get("vector_count", -1)) != D3S1_PREFIX_COUNT:
        raise SystemExit(
            f"d3s1 vector_count {doc.get('vector_count')} != {D3S1_PREFIX_COUNT}"
        )
    if len(doc["vectors"]) != D3S1_PREFIX_COUNT:
        raise SystemExit("d3s1 vectors length drift")
    if doc.get("content_sha256") != D3S1_PREFIX_CONTENT_SHA256:
        raise SystemExit(
            "d3s1 content_sha256 pin mismatch vs frozen prefix "
            f"(got {doc.get('content_sha256')})"
        )
    if doc.get("prior_fingerprint_prefix_hash") != D3S1_PREFIX_FINGERPRINT_HASH:
        raise SystemExit("d3s1 prior_fingerprint_prefix_hash pin mismatch")
    return doc


def _fingerprint_entries_for(
    d3s1_vectors: List[Dict[str, Any]], d3s2_vectors: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for v in d3s1_vectors:
        entries.append(
            {
                "id": v["id"],
                "kind": v["kind"],
                "mode": v["mode"],
                "fingerprint": d3s1_vector_fingerprint(v),
            }
        )
    for v in d3s2_vectors:
        entries.append(
            {
                "id": v["id"],
                "kind": v["kind"],
                "mode": v["mode"],
                "fingerprint": d3s2_vector_fingerprint(v),
            }
        )
    return entries


def _chain_hash(entries: List[Dict[str, Any]]) -> str:
    material = "".join(e["fingerprint"] for e in entries).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def freeze_d3s2_100_prefix(
    d3s1_vectors: List[Dict[str, Any]], smoke_vectors: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Fail-closed freeze of the prior 100-vector main artifact identity."""
    if len(d3s1_vectors) != D3S1_PREFIX_COUNT:
        raise SystemExit("100-prefix d3s1 length drift")
    if len(smoke_vectors) != D3S2_SMOKE_COUNT:
        raise SystemExit("100-prefix smoke length drift")
    entries = _fingerprint_entries_for(d3s1_vectors, smoke_vectors)
    chain = _chain_hash(entries)
    if chain != D3S2_100_FINGERPRINT_HASH:
        raise SystemExit(
            "100-prefix fingerprint chain drift vs frozen main pin "
            f"(got {chain})"
        )
    # Rebuild the historical 100-vector document content hash (scope of that
    # release used the prior SCOPE text; pin content_sha256 of the on-disk
    # prior main artifact by recomputing fingerprints+vector identity only).
    # Vector id/order/rows/calls/expected are re-checked in check() against
    # the rebuilt smoke+d3s1 material; chain pin above is the strong freeze.
    return entries


def build_document() -> Dict[str, Any]:
    prefix_doc = freeze_d3s1_prefix()
    prefix_vectors = prefix_doc["vectors"]
    smoke_vectors = build_d3s2_smoke_vectors()
    mode25_vectors = build_d3s2_mode25_slice_vectors()
    mode26_vectors = build_d3s2_mode26_slice_vectors()
    mode24_vectors = build_d3s2_mode24_slice_vectors()
    mode23_vectors = build_d3s2_mode23_slice_vectors()
    mode22_vectors = build_d3s2_mode22_slice_vectors()
    mode21_vectors = build_d3s2_mode21_slice_vectors()
    p0a_vectors = build_d3s2_p0a_slice_vectors()
    p0b_vectors = build_d3s2_p0b_slice_vectors()
    p0c_vectors = build_d3s2_p0c_slice_vectors()
    p0d_vectors = build_d3s2_p0d_slice_vectors()
    p1a_vectors = build_d3s2_p1a_slice_vectors()
    p1d_vectors = build_d3s2_p1d_slice_vectors()
    p1d2_vectors = build_d3s2_p1d2_slice_vectors()
    p1b1_vectors = build_d3s2_p1b1_slice_vectors()
    p1b2_vectors = build_d3s2_p1b2_slice_vectors()
    p1c1_vectors = build_d3s2_p1c1_slice_vectors()
    p1c2_vectors = build_d3s2_p1c2_slice_vectors()
    suffix_vectors = (
        smoke_vectors
        + mode25_vectors
        + mode26_vectors
        + mode24_vectors
        + mode23_vectors
        + mode22_vectors
        + mode21_vectors
        + p0a_vectors
        + p0b_vectors
        + p0c_vectors
        + p0d_vectors
        + p1a_vectors
        + p1d_vectors
        + p1d2_vectors
        + p1b1_vectors
        + p1b2_vectors
        + p1c1_vectors
        + p1c2_vectors
    )
    if len(suffix_vectors) != D3S2_SUFFIX_COUNT:
        raise SystemExit("suffix assembly count drift")
    vectors = list(prefix_vectors) + list(suffix_vectors)

    # Fail-closed: first 100 == prior main (94 D3S1 + 6 smoke).
    freeze_d3s2_100_prefix(prefix_vectors, smoke_vectors)

    prior_fingerprints = _fingerprint_entries_for(prefix_vectors, suffix_vectors)
    prior_prefix_hash = _chain_hash(prior_fingerprints)

    # Retained D3-S1-only fingerprint chain pin (first 94).
    d3s1_only_hash = _chain_hash(prior_fingerprints[:D3S1_PREFIX_COUNT])
    if d3s1_only_hash != D3S1_PREFIX_FINGERPRINT_HASH:
        raise SystemExit(
            "prefix fingerprint chain drift vs frozen D3-S1 pin "
            f"(got {d3s1_only_hash})"
        )

    # Retained 100-vector chain pin.
    hundred_hash = _chain_hash(prior_fingerprints[:D3S2_100_PREFIX_COUNT])
    if hundred_hash != D3S2_100_FINGERPRINT_HASH:
        raise SystemExit(
            "100-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_hash})"
        )

    # Retained 102-vector chain pin (100 + Mode25 slice).
    hundred_two_hash = _chain_hash(prior_fingerprints[:D3S2_102_PREFIX_COUNT])
    if hundred_two_hash != D3S2_102_FINGERPRINT_HASH:
        raise SystemExit(
            "102-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_two_hash})"
        )

    # Retained 104-vector chain pin (102 + Mode26).
    hundred_four_hash = _chain_hash(prior_fingerprints[:D3S2_104_PREFIX_COUNT])
    if hundred_four_hash != D3S2_104_FINGERPRINT_HASH:
        raise SystemExit(
            "104-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_four_hash})"
        )

    # Retained 106-vector chain pin (104 + Mode24 = prior main).
    hundred_six_hash = _chain_hash(prior_fingerprints[:D3S2_106_PREFIX_COUNT])
    if hundred_six_hash != D3S2_106_FINGERPRINT_HASH:
        raise SystemExit(
            "106-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_six_hash})"
        )

    # Retained 108-vector chain pin (106 + Mode23 = prior main).
    hundred_eight_hash = _chain_hash(prior_fingerprints[:D3S2_108_PREFIX_COUNT])
    if hundred_eight_hash != D3S2_108_FINGERPRINT_HASH:
        raise SystemExit(
            "108-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_eight_hash})"
        )

    # Retained 110-vector chain pin (108 + Mode22 = prior main).
    hundred_ten_hash = _chain_hash(prior_fingerprints[:D3S2_110_PREFIX_COUNT])
    if hundred_ten_hash != D3S2_110_FINGERPRINT_HASH:
        raise SystemExit(
            "110-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_ten_hash})"
        )

    # Retained 112-vector chain pin (110 + Mode21 = prior main).
    hundred_twelve_hash = _chain_hash(
        prior_fingerprints[:D3S2_112_PREFIX_COUNT]
    )
    if hundred_twelve_hash != D3S2_112_FINGERPRINT_HASH:
        raise SystemExit(
            "112-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_twelve_hash})"
        )

    # Retained 113-vector chain pin (112 + P0-A = origin/main).
    hundred_thirteen_hash = _chain_hash(
        prior_fingerprints[:D3S2_113_PREFIX_COUNT]
    )
    if hundred_thirteen_hash != D3S2_113_FINGERPRINT_HASH:
        raise SystemExit(
            "113-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_thirteen_hash})"
        )

    # Retained 114-vector chain pin (113 + P0-B = origin/main before P0-C).
    hundred_fourteen_hash = _chain_hash(
        prior_fingerprints[:D3S2_114_PREFIX_COUNT]
    )
    if hundred_fourteen_hash != D3S2_114_FINGERPRINT_HASH:
        raise SystemExit(
            "114-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_fourteen_hash})"
        )

    # Retained 115-vector chain pin (114 + P0-C = origin/main before P0-D).
    hundred_fifteen_hash = _chain_hash(
        prior_fingerprints[:D3S2_115_PREFIX_COUNT]
    )
    if hundred_fifteen_hash != D3S2_115_FINGERPRINT_HASH:
        raise SystemExit(
            "115-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_fifteen_hash})"
        )

    # Retained 119-vector chain pin (115 + P0-D = origin/main before P1-A).
    hundred_nineteen_hash = _chain_hash(
        prior_fingerprints[:D3S2_119_PREFIX_COUNT]
    )
    if hundred_nineteen_hash != D3S2_119_FINGERPRINT_HASH:
        raise SystemExit(
            "119-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_nineteen_hash})"
        )

    # Retained 125-vector chain pin (119 + P1-A = origin/main before P1-D).
    hundred_twenty_five_hash = _chain_hash(
        prior_fingerprints[:D3S2_125_PREFIX_COUNT]
    )
    if hundred_twenty_five_hash != D3S2_125_FINGERPRINT_HASH:
        raise SystemExit(
            "125-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_twenty_five_hash})"
        )

    # Retained 127-vector chain pin (125 + P1-D = origin/main before P1-D2).
    hundred_twenty_seven_hash = _chain_hash(
        prior_fingerprints[:D3S2_127_PREFIX_COUNT]
    )
    if hundred_twenty_seven_hash != D3S2_127_FINGERPRINT_HASH:
        raise SystemExit(
            "127-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_twenty_seven_hash})"
        )

    # Retained 128-vector chain pin (127 + P1-D2 = origin/main before P1-B1).
    hundred_twenty_eight_hash = _chain_hash(
        prior_fingerprints[:D3S2_128_PREFIX_COUNT]
    )
    if hundred_twenty_eight_hash != D3S2_128_FINGERPRINT_HASH:
        raise SystemExit(
            "128-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_twenty_eight_hash})"
        )

    # Retained 130-vector chain pin (128 + P1-B1 = origin/main before P1-B2).
    hundred_thirty_hash = _chain_hash(
        prior_fingerprints[:D3S2_130_PREFIX_COUNT]
    )
    if hundred_thirty_hash != D3S2_130_FINGERPRINT_HASH:
        raise SystemExit(
            "130-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_thirty_hash})"
        )

    # Retained 133-vector chain pin (130 + P1-B2 = origin/main before P1-C1).
    hundred_thirty_three_hash = _chain_hash(
        prior_fingerprints[:D3S2_133_PREFIX_COUNT]
    )
    if hundred_thirty_three_hash != D3S2_133_FINGERPRINT_HASH:
        raise SystemExit(
            "133-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_thirty_three_hash})"
        )

    # Retained 139-vector chain pin (133 + P1-C1 = origin/main before P1-C2).
    hundred_thirty_nine_hash = _chain_hash(
        prior_fingerprints[:D3S2_139_PREFIX_COUNT]
    )
    if hundred_thirty_nine_hash != D3S2_139_FINGERPRINT_HASH:
        raise SystemExit(
            "139-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_thirty_nine_hash})"
        )

    required_kinds = sorted(
        set(prefix_doc["required_kinds"]) | set(D3S2_REQUIRED_KINDS)
    )

    doc: Dict[str, Any] = {
        "version": VERSION,
        "format": FORMAT,
        "scope": SCOPE,
        "vector_count": len(vectors),
        "d3s1_prefix_count": D3S1_PREFIX_COUNT,
        "d3s2_suffix_count": D3S2_SUFFIX_COUNT,
        "d3s2_100_prefix_count": D3S2_100_PREFIX_COUNT,
        "d3s2_102_prefix_count": D3S2_102_PREFIX_COUNT,
        "d3s2_104_prefix_count": D3S2_104_PREFIX_COUNT,
        "d3s2_106_prefix_count": D3S2_106_PREFIX_COUNT,
        "d3s2_108_prefix_count": D3S2_108_PREFIX_COUNT,
        "d3s2_110_prefix_count": D3S2_110_PREFIX_COUNT,
        "d3s2_112_prefix_count": D3S2_112_PREFIX_COUNT,
        "d3s2_113_prefix_count": D3S2_113_PREFIX_COUNT,
        "d3s2_114_prefix_count": D3S2_114_PREFIX_COUNT,
        "d3s2_115_prefix_count": D3S2_115_PREFIX_COUNT,
        "d3s2_119_prefix_count": D3S2_119_PREFIX_COUNT,
        "d3s2_125_prefix_count": D3S2_125_PREFIX_COUNT,
        "d3s2_127_prefix_count": D3S2_127_PREFIX_COUNT,
        "d3s2_128_prefix_count": D3S2_128_PREFIX_COUNT,
        "d3s2_130_prefix_count": D3S2_130_PREFIX_COUNT,
        "d3s2_133_prefix_count": D3S2_133_PREFIX_COUNT,
        "d3s2_139_prefix_count": D3S2_139_PREFIX_COUNT,
        "required_kinds": required_kinds,
        "workspace": {
            "key_capacity": 255,
            "value_capacity": 4096,
            "previous_key_capacity": 255,
            "ceiling_bytes": CEILING,
            "note": (
                "single 4096 value buffer; D3-S1 context 421/448; D3-S2 context "
                "306/320; no second 4096; mutation_calls always 0; 1 session = 1 mode"
            ),
        },
        "s1_authority": prefix_doc["s1_authority"],
        "s2_authority": prefix_doc["s2_authority"],
        "s3_authority": prefix_doc["s3_authority"],
        "s4_authority": prefix_doc["s4_authority"],
        "s5_authority": prefix_doc["s5_authority"],
        "d1_authority": prefix_doc["d1_authority"],
        "d3s1_prefix_authority": {
            "format": D3S1_FORMAT,
            "vector_count": D3S1_PREFIX_COUNT,
            "content_sha256": D3S1_PREFIX_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S1_PREFIX_FINGERPRINT_HASH,
            "generator": "tools/domain_scan_crossrow_vector_gen.py",
        },
        "d3s2_100_prefix_authority": {
            "vector_count": D3S2_100_PREFIX_COUNT,
            "content_sha256": D3S2_100_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_100_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 Mode21..26 "
                "empty-carrier smoke); Mode25/Mode26/Mode24/Mode23/Mode22/"
                "Mode21 slice vectors follow"
            ),
        },
        "d3s2_102_prefix_authority": {
            "vector_count": D3S2_102_PREFIX_COUNT,
            "content_sha256": D3S2_102_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_102_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "slice); Mode26/Mode24/Mode23/Mode22/Mode21 slice vectors follow"
            ),
        },
        "d3s2_104_prefix_authority": {
            "vector_count": D3S2_104_PREFIX_COUNT,
            "content_sha256": D3S2_104_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_104_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 slices); Mode24/Mode23/Mode22/Mode21 slice vectors "
                "follow"
            ),
        },
        "d3s2_106_prefix_authority": {
            "vector_count": D3S2_106_PREFIX_COUNT,
            "content_sha256": D3S2_106_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_106_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 + Mode24 slices); Mode23/Mode22/Mode21 slice "
                "vectors follow"
            ),
        },
        "d3s2_108_prefix_authority": {
            "vector_count": D3S2_108_PREFIX_COUNT,
            "content_sha256": D3S2_108_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_108_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 + Mode24 + Mode23 slices); Mode22/Mode21 slice "
                "vectors follow"
            ),
        },
        "d3s2_110_prefix_authority": {
            "vector_count": D3S2_110_PREFIX_COUNT,
            "content_sha256": D3S2_110_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_110_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 + Mode24 + Mode23 + Mode22 slices); Mode21 slice "
                "vectors follow"
            ),
        },
        "d3s2_112_prefix_authority": {
            "vector_count": D3S2_112_PREFIX_COUNT,
            "content_sha256": D3S2_112_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_112_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 18 d3s2 suffix "
                "through Mode21); P0-A multi-owner Mode25 vector follows"
            ),
        },
        "d3s2_113_prefix_authority": {
            "vector_count": D3S2_113_PREFIX_COUNT,
            "content_sha256": D3S2_113_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_113_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 19 d3s2 suffix "
                "through P0-A); P0-B Mode26 budget mid-focus resume vector follows"
            ),
        },
        "d3s2_114_prefix_authority": {
            "vector_count": D3S2_114_PREFIX_COUNT,
            "content_sha256": D3S2_114_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_114_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 20 d3s2 suffix "
                "through P0-B); P0-C Mode25 BIND Port terminal note0 vector follows"
            ),
        },
        "d3s2_115_prefix_authority": {
            "vector_count": D3S2_115_PREFIX_COUNT,
            "content_sha256": D3S2_115_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_115_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 21 d3s2 suffix "
                "through P0-C); P0-D Mode22 unexpected INDEX / true-primary "
                "ABSENT / primary PVD / pair subject residual vectors follow"
            ),
        },
        "d3s2_119_prefix_authority": {
            "vector_count": D3S2_119_PREFIX_COUNT,
            "content_sha256": D3S2_119_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_119_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 25 d3s2 suffix "
                "through P0-D); P1-A ordinary stream count under/over + empty-"
                "secondary declared>0 vectors follow"
            ),
        },
        "d3s2_125_prefix_authority": {
            "vector_count": D3S2_125_PREFIX_COUNT,
            "content_sha256": D3S2_125_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_125_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 31 d3s2 suffix "
                "through P1-A); P1-D profile mismatch / future_profile "
                "evaluator-off UNSUPPORTED vectors follow"
            ),
        },
        "d3s2_127_prefix_authority": {
            "vector_count": D3S2_127_PREFIX_COUNT,
            "content_sha256": D3S2_127_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_127_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 33 d3s2 suffix "
                "through P1-D); P1-D2 Mode21 count-green BIND-incomplete "
                "false-terminal probe vector follows"
            ),
        },
        "d3s2_128_prefix_authority": {
            "vector_count": D3S2_128_PREFIX_COUNT,
            "content_sha256": D3S2_128_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_128_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 34 d3s2 suffix "
                "through P1-D2); P1-B1 Mode22 CLEANUP ordinary-skip + Mode23 "
                "CLEANUP still-ordinary vectors follow"
            ),
        },
        "d3s2_130_prefix_authority": {
            "vector_count": D3S2_130_PREFIX_COUNT,
            "content_sha256": D3S2_130_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_130_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 36 d3s2 suffix "
                "through P1-B1); P1-B2 Mode24/25/26 CLEANUP still-ordinary "
                "vectors follow"
            ),
        },
        "d3s2_133_prefix_authority": {
            "vector_count": D3S2_133_PREFIX_COUNT,
            "content_sha256": D3S2_133_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_133_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 39 d3s2 suffix "
                "through P1-B2 / PR#69); P1-C1 Mode23 illegal-slot + "
                "equation/late fail vectors follow"
            ),
        },
        "d3s2_139_prefix_authority": {
            "vector_count": D3S2_139_PREFIX_COUNT,
            "content_sha256": D3S2_139_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_139_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of origin/main (94 D3S1 + 45 d3s2 suffix "
                "through P1-C1 / PR#70); P1-C2 Mode24/25 known-slot population "
                "legality residual vectors follow"
            ),
        },
        "prior_fingerprints": prior_fingerprints,
        "prior_fingerprint_prefix_hash": prior_prefix_hash,
        "sha256_procedure": SHA256_PROCEDURE,
        "content_sha256": "",
        "vectors": vectors,
    }
    doc["content_sha256"] = content_sha256_of_doc(doc)
    return doc


def generate(path: Path) -> None:
    doc = build_document()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")
    print(
        f"wrote {path} vectors={doc['vector_count']} "
        f"(d3s1_prefix={D3S1_PREFIX_COUNT} d3s2_suffix={D3S2_SUFFIX_COUNT}) "
        f"content_sha256={doc['content_sha256']}"
    )


def _fail_check(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _assert_prefix_identity(
    data_vectors: List[Dict[str, Any]], prefix_doc: Dict[str, Any]
) -> Optional[str]:
    """Fail-closed: first 94 vectors match d3s1 rebuild on fingerprint/order/
    expected/rows/calls (and id/kind/mode)."""
    exp_vecs = prefix_doc["vectors"]
    if len(data_vectors) < D3S1_PREFIX_COUNT:
        return f"vector list shorter than d3s1 prefix ({len(data_vectors)})"
    for i in range(D3S1_PREFIX_COUNT):
        got = data_vectors[i]
        exp = exp_vecs[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return (
                    f"prefix[{i}] {key} mismatch: {got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return f"prefix[{i}] {got.get('id')}: rows not byte-identical to d3s1"
        if got.get("calls") != exp.get("calls"):
            return f"prefix[{i}] {got.get('id')}: calls not identical to d3s1"
        if got.get("expected") != exp.get("expected"):
            return f"prefix[{i}] {got.get('id')}: expected not identical to d3s1"
        gf = d3s1_vector_fingerprint(got)
        ef = d3s1_vector_fingerprint(exp)
        if gf != ef:
            return (
                f"prefix[{i}] {got.get('id')}: fingerprint drift "
                f"{gf} vs {ef}"
            )
        if gf != prefix_doc["prior_fingerprints"][i]["fingerprint"]:
            return f"prefix[{i}] fingerprint vs d3s1 prior_fingerprints drift"
    return None


def check(
    path: Path,
    *,
    _expected_doc: Optional[Dict[str, Any]] = None,
    _prefix_doc: Optional[Dict[str, Any]] = None,
) -> int:
    """Validate on-disk oracle JSON against a fresh rebuild.

    Public CLI `check <path>` always rebuilds (default kwargs). Private
    optional kwargs are for self_test only: inject a previously generated
    and verified read-only expected_doc / prefix_doc so each tamper does
    not re-run build_document / freeze_d3s1_prefix. Callers must not mutate
    the injected docs.
    """
    if not path.is_file():
        return _fail_check(f"missing {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return check_data(
        data,
        path=path,
        expected_doc=_expected_doc,
        prefix_doc=_prefix_doc,
    )


def check_data(
    data: Dict[str, Any],
    *,
    path: Path,
    expected_doc: Optional[Dict[str, Any]] = None,
    prefix_doc: Optional[Dict[str, Any]] = None,
) -> int:
    """Core check body. None expected/prefix → independent rebuild (CLI path)."""
    if (expected_doc is None) != (prefix_doc is None):
        return _fail_check(
            "internal expected_doc/prefix_doc injection must be paired"
        )
    # When both are injected (self_test), reuse them and skip independent
    # slice rebuilds that only re-derive the same expected_doc vectors.
    reuse_expected = expected_doc is not None
    if expected_doc is None:
        expected_doc = build_document()
    if prefix_doc is None:
        prefix_doc = freeze_d3s1_prefix()

    if not data.get("vectors"):
        return _fail_check("vectors empty")
    if data.get("format") != FORMAT:
        return _fail_check(f"format mismatch {data.get('format')}")
    if data.get("version") != VERSION:
        return _fail_check("version mismatch")
    if int(data.get("vector_count", -1)) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"root vector_count {data.get('vector_count')} != pin "
            f"{EXPECTED_VECTOR_COUNT}"
        )
    if int(data.get("d3s1_prefix_count", -1)) != D3S1_PREFIX_COUNT:
        return _fail_check("d3s1_prefix_count pin mismatch")
    if int(data.get("d3s2_suffix_count", -1)) != D3S2_SUFFIX_COUNT:
        return _fail_check("d3s2_suffix_count pin mismatch")
    if int(data.get("d3s2_100_prefix_count", -1)) != D3S2_100_PREFIX_COUNT:
        return _fail_check("d3s2_100_prefix_count pin mismatch")
    if int(data.get("d3s2_102_prefix_count", -1)) != D3S2_102_PREFIX_COUNT:
        return _fail_check("d3s2_102_prefix_count pin mismatch")
    if int(data.get("d3s2_104_prefix_count", -1)) != D3S2_104_PREFIX_COUNT:
        return _fail_check("d3s2_104_prefix_count pin mismatch")
    if int(data.get("d3s2_106_prefix_count", -1)) != D3S2_106_PREFIX_COUNT:
        return _fail_check("d3s2_106_prefix_count pin mismatch")
    if int(data.get("d3s2_108_prefix_count", -1)) != D3S2_108_PREFIX_COUNT:
        return _fail_check("d3s2_108_prefix_count pin mismatch")
    if int(data.get("d3s2_110_prefix_count", -1)) != D3S2_110_PREFIX_COUNT:
        return _fail_check("d3s2_110_prefix_count pin mismatch")
    if int(data.get("d3s2_112_prefix_count", -1)) != D3S2_112_PREFIX_COUNT:
        return _fail_check("d3s2_112_prefix_count pin mismatch")
    if int(data.get("d3s2_113_prefix_count", -1)) != D3S2_113_PREFIX_COUNT:
        return _fail_check("d3s2_113_prefix_count pin mismatch")
    if int(data.get("d3s2_114_prefix_count", -1)) != D3S2_114_PREFIX_COUNT:
        return _fail_check("d3s2_114_prefix_count pin mismatch")
    if int(data.get("d3s2_115_prefix_count", -1)) != D3S2_115_PREFIX_COUNT:
        return _fail_check("d3s2_115_prefix_count pin mismatch")
    if data.get("required_kinds") != expected_doc["required_kinds"]:
        return _fail_check("required_kinds inventory mismatch")
    if not data.get("sha256_procedure"):
        return _fail_check("missing sha256_procedure")
    if not data.get("content_sha256"):
        return _fail_check("missing content_sha256")
    if data.get("content_sha256") != expected_doc.get("content_sha256"):
        return _fail_check("content_sha256 mismatch vs generator")
    if data.get("prior_fingerprint_prefix_hash") != expected_doc.get(
        "prior_fingerprint_prefix_hash"
    ):
        return _fail_check("prior_fingerprint_prefix_hash mismatch")

    # Frozen d3s1 prefix authority pins.
    auth = data.get("d3s1_prefix_authority") or {}
    if auth.get("content_sha256") != D3S1_PREFIX_CONTENT_SHA256:
        return _fail_check("d3s1_prefix_authority content_sha256 pin mismatch")
    if auth.get("prior_fingerprint_prefix_hash") != D3S1_PREFIX_FINGERPRINT_HASH:
        return _fail_check(
            "d3s1_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth.get("vector_count", -1)) != D3S1_PREFIX_COUNT:
        return _fail_check("d3s1_prefix_authority vector_count pin mismatch")

    # Frozen 100-vector prior-main pin.
    auth100 = data.get("d3s2_100_prefix_authority") or {}
    if auth100.get("content_sha256") != D3S2_100_CONTENT_SHA256:
        return _fail_check("d3s2_100_prefix_authority content_sha256 pin mismatch")
    if auth100.get("prior_fingerprint_prefix_hash") != D3S2_100_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_100_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth100.get("vector_count", -1)) != D3S2_100_PREFIX_COUNT:
        return _fail_check("d3s2_100_prefix_authority vector_count pin mismatch")

    # Frozen 102-vector prior-main pin (includes Mode25).
    auth102 = data.get("d3s2_102_prefix_authority") or {}
    if auth102.get("content_sha256") != D3S2_102_CONTENT_SHA256:
        return _fail_check("d3s2_102_prefix_authority content_sha256 pin mismatch")
    if auth102.get("prior_fingerprint_prefix_hash") != D3S2_102_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_102_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth102.get("vector_count", -1)) != D3S2_102_PREFIX_COUNT:
        return _fail_check("d3s2_102_prefix_authority vector_count pin mismatch")

    # Frozen 104-vector prior-main pin (includes Mode25+Mode26).
    auth104 = data.get("d3s2_104_prefix_authority") or {}
    if auth104.get("content_sha256") != D3S2_104_CONTENT_SHA256:
        return _fail_check("d3s2_104_prefix_authority content_sha256 pin mismatch")
    if auth104.get("prior_fingerprint_prefix_hash") != D3S2_104_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_104_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth104.get("vector_count", -1)) != D3S2_104_PREFIX_COUNT:
        return _fail_check("d3s2_104_prefix_authority vector_count pin mismatch")

    # Frozen 106-vector prior-main pin (includes Mode25+Mode26+Mode24).
    auth106 = data.get("d3s2_106_prefix_authority") or {}
    if auth106.get("content_sha256") != D3S2_106_CONTENT_SHA256:
        return _fail_check("d3s2_106_prefix_authority content_sha256 pin mismatch")
    if auth106.get("prior_fingerprint_prefix_hash") != D3S2_106_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_106_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth106.get("vector_count", -1)) != D3S2_106_PREFIX_COUNT:
        return _fail_check("d3s2_106_prefix_authority vector_count pin mismatch")

    # Frozen 108-vector prior-main pin (includes Mode25+Mode26+Mode24+Mode23).
    auth108 = data.get("d3s2_108_prefix_authority") or {}
    if auth108.get("content_sha256") != D3S2_108_CONTENT_SHA256:
        return _fail_check("d3s2_108_prefix_authority content_sha256 pin mismatch")
    if auth108.get("prior_fingerprint_prefix_hash") != D3S2_108_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_108_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth108.get("vector_count", -1)) != D3S2_108_PREFIX_COUNT:
        return _fail_check("d3s2_108_prefix_authority vector_count pin mismatch")

    # Frozen 110-vector prior-main pin (includes Mode25+Mode26+Mode24+Mode23+Mode22).
    auth110 = data.get("d3s2_110_prefix_authority") or {}
    if auth110.get("content_sha256") != D3S2_110_CONTENT_SHA256:
        return _fail_check("d3s2_110_prefix_authority content_sha256 pin mismatch")
    if auth110.get("prior_fingerprint_prefix_hash") != D3S2_110_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_110_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth110.get("vector_count", -1)) != D3S2_110_PREFIX_COUNT:
        return _fail_check("d3s2_110_prefix_authority vector_count pin mismatch")

    # Frozen 112-vector prior pin (includes Mode21; P0-A follows).
    auth112 = data.get("d3s2_112_prefix_authority") or {}
    if auth112.get("content_sha256") != D3S2_112_CONTENT_SHA256:
        return _fail_check("d3s2_112_prefix_authority content_sha256 pin mismatch")
    if auth112.get("prior_fingerprint_prefix_hash") != D3S2_112_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_112_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth112.get("vector_count", -1)) != D3S2_112_PREFIX_COUNT:
        return _fail_check("d3s2_112_prefix_authority vector_count pin mismatch")

    # Frozen 113-vector origin/main pin (includes P0-A; P0-B follows).
    auth113 = data.get("d3s2_113_prefix_authority") or {}
    if auth113.get("content_sha256") != D3S2_113_CONTENT_SHA256:
        return _fail_check("d3s2_113_prefix_authority content_sha256 pin mismatch")
    if auth113.get("prior_fingerprint_prefix_hash") != D3S2_113_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_113_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth113.get("vector_count", -1)) != D3S2_113_PREFIX_COUNT:
        return _fail_check("d3s2_113_prefix_authority vector_count pin mismatch")

    auth114 = data.get("d3s2_114_prefix_authority") or {}
    if auth114.get("content_sha256") != D3S2_114_CONTENT_SHA256:
        return _fail_check("d3s2_114_prefix_authority content_sha256 pin mismatch")
    if auth114.get("prior_fingerprint_prefix_hash") != D3S2_114_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_114_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth114.get("vector_count", -1)) != D3S2_114_PREFIX_COUNT:
        return _fail_check("d3s2_114_prefix_authority vector_count pin mismatch")

    auth115 = data.get("d3s2_115_prefix_authority") or {}
    if auth115.get("content_sha256") != D3S2_115_CONTENT_SHA256:
        return _fail_check("d3s2_115_prefix_authority content_sha256 pin mismatch")
    if auth115.get("prior_fingerprint_prefix_hash") != D3S2_115_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_115_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth115.get("vector_count", -1)) != D3S2_115_PREFIX_COUNT:
        return _fail_check("d3s2_115_prefix_authority vector_count pin mismatch")

    if int(data.get("d3s2_119_prefix_count", -1)) != D3S2_119_PREFIX_COUNT:
        return _fail_check("d3s2_119_prefix_count pin mismatch")
    auth119 = data.get("d3s2_119_prefix_authority") or {}
    if auth119.get("content_sha256") != D3S2_119_CONTENT_SHA256:
        return _fail_check("d3s2_119_prefix_authority content_sha256 pin mismatch")
    if auth119.get("prior_fingerprint_prefix_hash") != D3S2_119_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_119_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth119.get("vector_count", -1)) != D3S2_119_PREFIX_COUNT:
        return _fail_check("d3s2_119_prefix_authority vector_count pin mismatch")

    if int(data.get("d3s2_125_prefix_count", -1)) != D3S2_125_PREFIX_COUNT:
        return _fail_check("d3s2_125_prefix_count pin mismatch")
    auth125 = data.get("d3s2_125_prefix_authority") or {}
    if auth125.get("content_sha256") != D3S2_125_CONTENT_SHA256:
        return _fail_check("d3s2_125_prefix_authority content_sha256 pin mismatch")
    if auth125.get("prior_fingerprint_prefix_hash") != D3S2_125_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_125_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth125.get("vector_count", -1)) != D3S2_125_PREFIX_COUNT:
        return _fail_check("d3s2_125_prefix_authority vector_count pin mismatch")

    if int(data.get("d3s2_127_prefix_count", -1)) != D3S2_127_PREFIX_COUNT:
        return _fail_check("d3s2_127_prefix_count pin mismatch")
    auth127 = data.get("d3s2_127_prefix_authority") or {}
    if auth127.get("content_sha256") != D3S2_127_CONTENT_SHA256:
        return _fail_check("d3s2_127_prefix_authority content_sha256 pin mismatch")
    if auth127.get("prior_fingerprint_prefix_hash") != D3S2_127_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_127_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth127.get("vector_count", -1)) != D3S2_127_PREFIX_COUNT:
        return _fail_check("d3s2_127_prefix_authority vector_count pin mismatch")
    if int(data.get("d3s2_128_prefix_count", -1)) != D3S2_128_PREFIX_COUNT:
        return _fail_check("d3s2_128_prefix_count pin mismatch")
    auth128 = data.get("d3s2_128_prefix_authority") or {}
    if auth128.get("content_sha256") != D3S2_128_CONTENT_SHA256:
        return _fail_check("d3s2_128_prefix_authority content_sha256 pin mismatch")
    if auth128.get("prior_fingerprint_prefix_hash") != D3S2_128_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_128_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth128.get("vector_count", -1)) != D3S2_128_PREFIX_COUNT:
        return _fail_check("d3s2_128_prefix_authority vector_count pin mismatch")
    if int(data.get("d3s2_130_prefix_count", -1)) != D3S2_130_PREFIX_COUNT:
        return _fail_check("d3s2_130_prefix_count pin mismatch")
    auth130 = data.get("d3s2_130_prefix_authority") or {}
    if auth130.get("content_sha256") != D3S2_130_CONTENT_SHA256:
        return _fail_check("d3s2_130_prefix_authority content_sha256 pin mismatch")
    if auth130.get("prior_fingerprint_prefix_hash") != D3S2_130_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_130_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth130.get("vector_count", -1)) != D3S2_130_PREFIX_COUNT:
        return _fail_check("d3s2_130_prefix_authority vector_count pin mismatch")
    if int(data.get("d3s2_133_prefix_count", -1)) != D3S2_133_PREFIX_COUNT:
        return _fail_check("d3s2_133_prefix_count pin mismatch")
    auth133 = data.get("d3s2_133_prefix_authority") or {}
    if auth133.get("content_sha256") != D3S2_133_CONTENT_SHA256:
        return _fail_check("d3s2_133_prefix_authority content_sha256 pin mismatch")
    if auth133.get("prior_fingerprint_prefix_hash") != D3S2_133_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_133_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth133.get("vector_count", -1)) != D3S2_133_PREFIX_COUNT:
        return _fail_check("d3s2_133_prefix_authority vector_count pin mismatch")
    if int(data.get("d3s2_139_prefix_count", -1)) != D3S2_139_PREFIX_COUNT:
        return _fail_check("d3s2_139_prefix_count pin mismatch")
    auth139 = data.get("d3s2_139_prefix_authority") or {}
    if auth139.get("content_sha256") != D3S2_139_CONTENT_SHA256:
        return _fail_check("d3s2_139_prefix_authority content_sha256 pin mismatch")
    if auth139.get("prior_fingerprint_prefix_hash") != D3S2_139_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_139_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth139.get("vector_count", -1)) != D3S2_139_PREFIX_COUNT:
        return _fail_check("d3s2_139_prefix_authority vector_count pin mismatch")

    vectors = data["vectors"]
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"vector count {len(vectors)} != pin {EXPECTED_VECTOR_COUNT}"
        )
    # Full-object prefix equality: first 115 vectors must match rebuild of
    # frozen origin/main (94 d3s1 + 21 d3s2 through P0-C).
    expected_115 = expected_doc["vectors"][:D3S2_115_PREFIX_COUNT]
    if vectors[:D3S2_115_PREFIX_COUNT] != expected_115:
        for i in range(D3S2_115_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_115[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_115[i])
            if vectors[i] != expected_115[i] or fp_got != fp_exp:
                return _fail_check(
                    f"115-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("115-prefix full-object mismatch")

    # Full-object 119-prefix equality (115 + P0-D; origin/main before P1-A).
    expected_119 = expected_doc["vectors"][:D3S2_119_PREFIX_COUNT]
    if vectors[:D3S2_119_PREFIX_COUNT] != expected_119:
        for i in range(D3S2_119_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_119[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_119[i])
            if vectors[i] != expected_119[i] or fp_got != fp_exp:
                return _fail_check(
                    f"119-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("119-prefix full-object mismatch")
    hundred_nineteen_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_119_PREFIX_COUNT)
        ]
    )
    if hundred_nineteen_chain != D3S2_119_FINGERPRINT_HASH:
        return _fail_check(
            f"119-prefix fingerprint chain pin fail (got {hundred_nineteen_chain})"
        )

    # Full-object 125-prefix equality (119 + P1-A; origin/main before P1-D).
    expected_125 = expected_doc["vectors"][:D3S2_125_PREFIX_COUNT]
    if vectors[:D3S2_125_PREFIX_COUNT] != expected_125:
        for i in range(D3S2_125_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_125[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_125[i])
            if vectors[i] != expected_125[i] or fp_got != fp_exp:
                return _fail_check(
                    f"125-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("125-prefix full-object mismatch")
    hundred_twenty_five_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_125_PREFIX_COUNT)
        ]
    )
    if hundred_twenty_five_chain != D3S2_125_FINGERPRINT_HASH:
        return _fail_check(
            f"125-prefix fingerprint chain pin fail "
            f"(got {hundred_twenty_five_chain})"
        )

    # Full-object 127-prefix equality (125 + P1-D; origin/main before P1-D2).
    expected_127 = expected_doc["vectors"][:D3S2_127_PREFIX_COUNT]
    if vectors[:D3S2_127_PREFIX_COUNT] != expected_127:
        for i in range(D3S2_127_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_127[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_127[i])
            if vectors[i] != expected_127[i] or fp_got != fp_exp:
                return _fail_check(
                    f"127-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("127-prefix full-object mismatch")
    hundred_twenty_seven_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_127_PREFIX_COUNT)
        ]
    )
    if hundred_twenty_seven_chain != D3S2_127_FINGERPRINT_HASH:
        return _fail_check(
            f"127-prefix fingerprint chain pin fail "
            f"(got {hundred_twenty_seven_chain})"
        )

    # Full-object 128-prefix equality (127 + P1-D2; origin/main before P1-B1).
    expected_128 = expected_doc["vectors"][:D3S2_128_PREFIX_COUNT]
    if vectors[:D3S2_128_PREFIX_COUNT] != expected_128:
        for i in range(D3S2_128_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_128[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_128[i])
            if vectors[i] != expected_128[i] or fp_got != fp_exp:
                return _fail_check(
                    f"128-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("128-prefix full-object mismatch")
    hundred_twenty_eight_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_128_PREFIX_COUNT)
        ]
    )
    if hundred_twenty_eight_chain != D3S2_128_FINGERPRINT_HASH:
        return _fail_check(
            f"128-prefix fingerprint chain pin fail "
            f"(got {hundred_twenty_eight_chain})"
        )

    # Full-object 130-prefix equality (128 + P1-B1; origin/main before P1-B2).
    # Absolute invariant: existing 130 full-object prefix must not change.
    expected_130 = expected_doc["vectors"][:D3S2_130_PREFIX_COUNT]
    if vectors[:D3S2_130_PREFIX_COUNT] != expected_130:
        for i in range(D3S2_130_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_130[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_130[i])
            if vectors[i] != expected_130[i] or fp_got != fp_exp:
                return _fail_check(
                    f"130-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("130-prefix full-object mismatch")
    hundred_thirty_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_130_PREFIX_COUNT)
        ]
    )
    if hundred_thirty_chain != D3S2_130_FINGERPRINT_HASH:
        return _fail_check(
            f"130-prefix fingerprint chain pin fail "
            f"(got {hundred_thirty_chain})"
        )

    # Full-object 133-prefix equality (130 + P1-B2; origin/main before P1-C1).
    expected_133 = expected_doc["vectors"][:D3S2_133_PREFIX_COUNT]
    if vectors[:D3S2_133_PREFIX_COUNT] != expected_133:
        for i in range(D3S2_133_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_133[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_133[i])
            if vectors[i] != expected_133[i] or fp_got != fp_exp:
                return _fail_check(
                    f"133-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("133-prefix full-object mismatch")
    hundred_thirty_three_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_133_PREFIX_COUNT)
        ]
    )
    if hundred_thirty_three_chain != D3S2_133_FINGERPRINT_HASH:
        return _fail_check(
            f"133-prefix fingerprint chain pin fail "
            f"(got {hundred_thirty_three_chain})"
        )

    # Full-object 139-prefix equality (133 + P1-C1; origin/main before P1-C2).
    expected_139 = expected_doc["vectors"][:D3S2_139_PREFIX_COUNT]
    if vectors[:D3S2_139_PREFIX_COUNT] != expected_139:
        for i in range(D3S2_139_PREFIX_COUNT):
            if i < D3S1_PREFIX_COUNT:
                fp_got = d3s1_vector_fingerprint(vectors[i])
                fp_exp = d3s1_vector_fingerprint(expected_139[i])
            else:
                fp_got = d3s2_vector_fingerprint(vectors[i])
                fp_exp = d3s2_vector_fingerprint(expected_139[i])
            if vectors[i] != expected_139[i] or fp_got != fp_exp:
                return _fail_check(
                    f"139-prefix full-object mismatch at [{i}] "
                    f"id={vectors[i].get('id')}"
                )
        return _fail_check("139-prefix full-object mismatch")
    hundred_thirty_nine_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_139_PREFIX_COUNT)
        ]
    )
    if hundred_thirty_nine_chain != D3S2_139_FINGERPRINT_HASH:
        return _fail_check(
            f"139-prefix fingerprint chain pin fail "
            f"(got {hundred_thirty_nine_chain})"
        )

    err = _assert_prefix_identity(vectors, prefix_doc)
    if err:
        return _fail_check(err)

    # First 100 vectors: id/order/rows/calls/expected/fingerprint vs rebuild.
    if reuse_expected:
        expected_100 = expected_doc["vectors"][:D3S2_100_PREFIX_COUNT]
    else:
        smoke_rebuild = build_d3s2_smoke_vectors()
        expected_100 = list(prefix_doc["vectors"]) + list(smoke_rebuild)
    if len(expected_100) != D3S2_100_PREFIX_COUNT:
        return _fail_check("internal 100-prefix rebuild length drift")
    for i in range(D3S2_100_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_100[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"100-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
    hundred_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_100_PREFIX_COUNT)
        ]
    )
    if hundred_chain != D3S2_100_FINGERPRINT_HASH:
        return _fail_check(
            f"100-prefix fingerprint chain pin fail (got {hundred_chain})"
        )

    # First 102 vectors: id/order/rows/calls/expected/fingerprint vs rebuild
    # (94 D3S1 + 6 smoke + Mode25 slice = frozen prior main).
    if reuse_expected:
        expected_102 = expected_doc["vectors"][:D3S2_102_PREFIX_COUNT]
    else:
        mode25_rebuild = build_d3s2_mode25_slice_vectors()
        expected_102 = list(expected_100) + list(mode25_rebuild)
    if len(expected_102) != D3S2_102_PREFIX_COUNT:
        return _fail_check("internal 102-prefix rebuild length drift")
    for i in range(D3S2_102_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_102[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"102-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
    hundred_two_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_102_PREFIX_COUNT)
        ]
    )
    if hundred_two_chain != D3S2_102_FINGERPRINT_HASH:
        return _fail_check(
            f"102-prefix fingerprint chain pin fail (got {hundred_two_chain})"
        )

    # First 104 vectors: id/order/rows/calls/expected/fingerprint vs rebuild
    # (94 D3S1 + 6 smoke + Mode25 + Mode26 = frozen prior main).
    if reuse_expected:
        expected_104 = expected_doc["vectors"][:D3S2_104_PREFIX_COUNT]
    else:
        mode26_rebuild = build_d3s2_mode26_slice_vectors()
        expected_104 = list(expected_102) + list(mode26_rebuild)
    if len(expected_104) != D3S2_104_PREFIX_COUNT:
        return _fail_check("internal 104-prefix rebuild length drift")
    for i in range(D3S2_104_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_104[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"104-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
    hundred_four_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_104_PREFIX_COUNT)
        ]
    )
    if hundred_four_chain != D3S2_104_FINGERPRINT_HASH:
        return _fail_check(
            f"104-prefix fingerprint chain pin fail (got {hundred_four_chain})"
        )

    # First 106 vectors: id/order/rows/calls/expected/fingerprint vs rebuild
    # (94 D3S1 + 6 smoke + Mode25 + Mode26 + Mode24 = frozen prior main).
    # Per-field diagnostics retained first; then full object equality so
    # ownership/notes/refs/etc. cannot silently drift (append-only pin).
    if reuse_expected:
        expected_106 = expected_doc["vectors"][:D3S2_106_PREFIX_COUNT]
    else:
        mode24_rebuild = build_d3s2_mode24_slice_vectors()
        expected_106 = list(expected_104) + list(mode24_rebuild)
    if len(expected_106) != D3S2_106_PREFIX_COUNT:
        return _fail_check("internal 106-prefix rebuild length drift")
    for i in range(D3S2_106_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_106[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"106-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        # Full object equality after targeted diagnostics (covers ownership,
        # notes, d1_refs, source_ref, peer_ref, row_refs, faults, alt_rows,
        # candidate_binding, and any future vector field).
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"106-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_six_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_106_PREFIX_COUNT)
        ]
    )
    if hundred_six_chain != D3S2_106_FINGERPRINT_HASH:
        return _fail_check(
            f"106-prefix fingerprint chain pin fail (got {hundred_six_chain})"
        )

    # First 108 vectors: id/order/rows/calls/expected/fingerprint + full
    # object equality vs rebuild (94 D3S1 + 6 smoke + Mode25 + Mode26 +
    # Mode24 + Mode23 = frozen prior main). Mode22 must not rewrite any
    # prior ownership/notes/refs byte.
    if reuse_expected:
        expected_108 = expected_doc["vectors"][:D3S2_108_PREFIX_COUNT]
    else:
        mode23_rebuild = build_d3s2_mode23_slice_vectors()
        expected_108 = list(expected_106) + list(mode23_rebuild)
    if len(expected_108) != D3S2_108_PREFIX_COUNT:
        return _fail_check("internal 108-prefix rebuild length drift")
    for i in range(D3S2_108_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_108[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"108-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"108-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_eight_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_108_PREFIX_COUNT)
        ]
    )
    if hundred_eight_chain != D3S2_108_FINGERPRINT_HASH:
        return _fail_check(
            f"108-prefix fingerprint chain pin fail (got {hundred_eight_chain})"
        )

    # First 110 vectors: id/order/rows/calls/expected/fingerprint + full
    # object equality vs rebuild (94 D3S1 + 6 smoke + Mode25 + Mode26 +
    # Mode24 + Mode23 + Mode22 = frozen prior main). Mode21 must not rewrite
    # any prior ownership/notes/refs byte.
    if reuse_expected:
        expected_110 = expected_doc["vectors"][:D3S2_110_PREFIX_COUNT]
    else:
        mode22_rebuild = build_d3s2_mode22_slice_vectors()
        expected_110 = list(expected_108) + list(mode22_rebuild)
    if len(expected_110) != D3S2_110_PREFIX_COUNT:
        return _fail_check("internal 110-prefix rebuild length drift")
    for i in range(D3S2_110_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_110[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"110-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"110-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"110-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"110-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"110-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"110-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"110-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_ten_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_110_PREFIX_COUNT)
        ]
    )
    if hundred_ten_chain != D3S2_110_FINGERPRINT_HASH:
        return _fail_check(
            f"110-prefix fingerprint chain pin fail (got {hundred_ten_chain})"
        )

    # First 112 vectors: full object equality vs rebuild (origin/main freeze).
    # P0-A must not rewrite any prior ownership/notes/refs/expected byte.
    if reuse_expected:
        expected_112 = expected_doc["vectors"][:D3S2_112_PREFIX_COUNT]
    else:
        mode21_rebuild = build_d3s2_mode21_slice_vectors()
        expected_112 = list(expected_110) + list(mode21_rebuild)
    if len(expected_112) != D3S2_112_PREFIX_COUNT:
        return _fail_check("internal 112-prefix rebuild length drift")
    for i in range(D3S2_112_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_112[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"112-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"112-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"112-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"112-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"112-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"112-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"112-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_twelve_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_112_PREFIX_COUNT)
        ]
    )
    if hundred_twelve_chain != D3S2_112_FINGERPRINT_HASH:
        return _fail_check(
            f"112-prefix fingerprint chain pin fail (got {hundred_twelve_chain})"
        )

    # First 113 vectors: full object equality vs rebuild (origin/main freeze).
    # P0-B must not rewrite any prior ownership/notes/refs/expected byte.
    if reuse_expected:
        expected_113 = expected_doc["vectors"][:D3S2_113_PREFIX_COUNT]
    else:
        p0a_rebuild = build_d3s2_p0a_slice_vectors()
        expected_113 = list(expected_112) + list(p0a_rebuild)
    if len(expected_113) != D3S2_113_PREFIX_COUNT:
        return _fail_check("internal 113-prefix rebuild length drift")
    for i in range(D3S2_113_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_113[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"113-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"113-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"113-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"113-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"113-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"113-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"113-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_thirteen_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_113_PREFIX_COUNT)
        ]
    )
    if hundred_thirteen_chain != D3S2_113_FINGERPRINT_HASH:
        return _fail_check(
            f"113-prefix fingerprint chain pin fail (got {hundred_thirteen_chain})"
        )

    # First 114 vectors: full object equality vs rebuild (origin/main freeze).
    # P0-C must not rewrite any prior ownership/notes/refs/expected byte.
    if reuse_expected:
        expected_114 = expected_doc["vectors"][:D3S2_114_PREFIX_COUNT]
    else:
        p0b_rebuild = build_d3s2_p0b_slice_vectors()
        expected_114 = list(expected_113) + list(p0b_rebuild)
    if len(expected_114) != D3S2_114_PREFIX_COUNT:
        return _fail_check("internal 114-prefix rebuild length drift")
    for i in range(D3S2_114_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_114[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"114-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"114-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"114-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"114-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"114-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"114-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"114-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_fourteen_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_114_PREFIX_COUNT)
        ]
    )
    if hundred_fourteen_chain != D3S2_114_FINGERPRINT_HASH:
        return _fail_check(
            f"114-prefix fingerprint chain pin fail (got {hundred_fourteen_chain})"
        )

    # prior_fingerprints order/identity.
    got_fps = data.get("prior_fingerprints")
    exp_fps = expected_doc["prior_fingerprints"]
    if not isinstance(got_fps, list) or len(got_fps) != len(exp_fps):
        return _fail_check("prior_fingerprints length mismatch")
    for i, (g, e) in enumerate(zip(got_fps, exp_fps)):
        if g.get("id") != e.get("id") or g.get("fingerprint") != e.get(
            "fingerprint"
        ):
            return _fail_check(
                f"append-prefix drift at prior_fingerprints[{i}] "
                f"id={g.get('id')!r} vs {e.get('id')!r}"
            )

    # First 94 prior_fingerprints must equal frozen d3s1 chain.
    for i in range(D3S1_PREFIX_COUNT):
        if (
            got_fps[i].get("fingerprint")
            != prefix_doc["prior_fingerprints"][i]["fingerprint"]
        ):
            return _fail_check(
                f"prior_fingerprints[{i}] != frozen d3s1 fingerprint"
            )

    # Per-vector schema.
    kinds: Set[str] = set()
    for i, vec in enumerate(vectors):
        for k in VECTOR_KEYS:
            if k not in vec:
                return _fail_check(f"vector {i} missing key {k}")
        kinds.add(vec["kind"])
        extra = set(vec.keys()) - VECTOR_KEYS
        if extra:
            return _fail_check(f"vector {vec['id']} unexpected keys {extra}")
        for c in vec.get("calls", []):
            if not CALL_KEYS.issuperset(c.keys()):
                return _fail_check(f"call keys drift in {vec['id']}")
            op = c.get("op")
            if op not in CLOSED_CALL_OPS:
                return _fail_check(
                    f"{vec['id']}: call op {op!r} not in closed set"
                )
            if op in FORBIDDEN_CALL_OPS:
                return _fail_check(
                    f"{vec['id']}: TEST transport begin forbidden"
                )
            if "expected_status" not in c:
                return _fail_check(f"{vec['id']}: call missing expected_status")
            # Call-level checkpoint: explicit has_checkpoint only; no sentinel
            # defaults or name-string abuse. Existing calls omit the field (=0).
            has_cp = int(c.get("has_checkpoint", 0))
            if has_cp not in (0, 1):
                return _fail_check(
                    f"{vec['id']}: has_checkpoint must be 0|1, got {has_cp}"
                )
            if has_cp == 1:
                missing_cp = CHECKPOINT_REQUIRED_KEYS - set(c.keys())
                if missing_cp:
                    return _fail_check(
                        f"{vec['id']}: checkpoint missing fields {sorted(missing_cp)}"
                    )
                if int(c["cp_last_carrier_key_len"]) <= 0:
                    return _fail_check(
                        f"{vec['id']}: cp_last_carrier_key_len must be > 0"
                    )
                if "cp_last_carrier_key_hex" in c:
                    ck = from_hex(c["cp_last_carrier_key_hex"])
                    if len(ck) != int(c["cp_last_carrier_key_len"]):
                        return _fail_check(
                            f"{vec['id']}: cp_last_carrier_key_hex len mismatch"
                        )
            else:
                # has=0: forbid nonzero checkpoint payload (implicit defaults).
                for k in CHECKPOINT_REQUIRED_KEYS:
                    if k == "has_checkpoint":
                        continue
                    if k in c and int(c[k]) != 0:
                        return _fail_check(
                            f"{vec['id']}: {k} must be 0/absent when "
                            f"has_checkpoint=0"
                        )
                if "cp_last_carrier_key_hex" in c and c["cp_last_carrier_key_hex"]:
                    return _fail_check(
                        f"{vec['id']}: cp_last_carrier_key_hex forbidden when "
                        f"has_checkpoint=0"
                    )
            st = c["expected_status"]
            if op in HARNESS_CALL_OPS:
                if st != "VOID":
                    return _fail_check(
                        f"{vec['id']}: harness op {op} must be VOID"
                    )
            else:
                if st == "VOID" or not isinstance(st, str) or not st:
                    return _fail_check(
                        f"{vec['id']}: scanner op {op} missing status"
                    )
        exp_keys = set(vec["expected"].keys())
        if i < D3S1_PREFIX_COUNT:
            if exp_keys != D3S1_EXPECTED_KEYS:
                return _fail_check(
                    f"prefix expected keys drift in {vec['id']}: "
                    f"{exp_keys ^ D3S1_EXPECTED_KEYS}"
                )
        else:
            optional = exp_keys & D3S2_EXPECTED_OPTIONAL_KEYS
            base = exp_keys - D3S2_EXPECTED_OPTIONAL_KEYS
            if base != D3S2_EXPECTED_KEYS:
                return _fail_check(
                    f"suffix expected keys drift in {vec['id']}: "
                    f"{base ^ D3S2_EXPECTED_KEYS}"
                )
            if optional - D3S2_EXPECTED_OPTIONAL_KEYS:
                return _fail_check(
                    f"suffix unexpected optional keys in {vec['id']}: {optional}"
                )
            # Formal field only (reference model). Do not infer call count from
            # sticky status: Port shape poison can also produce CORRUPT without
            # note_terminal_corrupt. Slice-specific checks below own the exact
            # expected count for vectors that publish this field.
            if "note_count" in exp_keys:
                nc = int(vec["expected"]["note_count"])
                if nc < 0:
                    return _fail_check(
                        f"{vec['id']}: formal note_count must be non-negative"
                    )
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")
        # Same-txn multipass contract: exactly one begin in every d3s2 suffix.
        if i >= D3S1_PREFIX_COUNT:
            pt = vec["expected"].get("port_trace") or []
            begin_n = pt.count("begin:READ_ONLY")
            if begin_n != 1:
                return _fail_check(
                    f"{vec['id']}: same-txn requires exactly 1 begin:READ_ONLY "
                    f"in port_trace, got {begin_n} (two-txn list/count fail closed)"
                )

    # Suffix-specific pins: smoke [0..6) Mode25 [6..8) Mode26 [8..10)
    # Mode24 [10..12) Mode23 [12..14) Mode22 [14..16) Mode21 [16..18)
    # P0-A [18..19) P0-B [19..20) P0-C [20..21) P0-D [21..25) P1-A [25..31).
    suffix = vectors[D3S1_PREFIX_COUNT:]
    if len(suffix) != D3S2_SUFFIX_COUNT:
        return _fail_check("suffix length mismatch")
    smoke = suffix[:D3S2_SMOKE_COUNT]
    mode25 = suffix[D3S2_SMOKE_COUNT : D3S2_SMOKE_COUNT + D3S2_MODE25_SLICE_COUNT]
    mode26_start = D3S2_SMOKE_COUNT + D3S2_MODE25_SLICE_COUNT
    mode26 = suffix[mode26_start : mode26_start + D3S2_MODE26_SLICE_COUNT]
    mode24_start = mode26_start + D3S2_MODE26_SLICE_COUNT
    mode24 = suffix[mode24_start : mode24_start + D3S2_MODE24_SLICE_COUNT]
    mode23_start = mode24_start + D3S2_MODE24_SLICE_COUNT
    mode23 = suffix[mode23_start : mode23_start + D3S2_MODE23_SLICE_COUNT]
    mode22_start = mode23_start + D3S2_MODE23_SLICE_COUNT
    mode22 = suffix[mode22_start : mode22_start + D3S2_MODE22_SLICE_COUNT]
    mode21_start = mode22_start + D3S2_MODE22_SLICE_COUNT
    mode21 = suffix[mode21_start : mode21_start + D3S2_MODE21_SLICE_COUNT]
    p0a_start = mode21_start + D3S2_MODE21_SLICE_COUNT
    p0a = suffix[p0a_start : p0a_start + D3S2_P0A_SLICE_COUNT]
    p0b_start = p0a_start + D3S2_P0A_SLICE_COUNT
    p0b = suffix[p0b_start : p0b_start + D3S2_P0B_SLICE_COUNT]
    p0c_start = p0b_start + D3S2_P0B_SLICE_COUNT
    p0c = suffix[p0c_start : p0c_start + D3S2_P0C_SLICE_COUNT]
    p0d_start = p0c_start + D3S2_P0C_SLICE_COUNT
    p0d = suffix[p0d_start : p0d_start + D3S2_P0D_SLICE_COUNT]
    p1a_start = p0d_start + D3S2_P0D_SLICE_COUNT
    p1a = suffix[p1a_start : p1a_start + D3S2_P1A_SLICE_COUNT]
    p1d_start = p1a_start + D3S2_P1A_SLICE_COUNT
    p1d = suffix[p1d_start : p1d_start + D3S2_P1D_SLICE_COUNT]
    p1d2_start = p1d_start + D3S2_P1D_SLICE_COUNT
    p1d2 = suffix[p1d2_start : p1d2_start + D3S2_P1D2_SLICE_COUNT]
    p1b1_start = p1d2_start + D3S2_P1D2_SLICE_COUNT
    p1b1 = suffix[p1b1_start : p1b1_start + D3S2_P1B1_SLICE_COUNT]
    p1b2_start = p1b1_start + D3S2_P1B1_SLICE_COUNT
    p1b2 = suffix[p1b2_start : p1b2_start + D3S2_P1B2_SLICE_COUNT]
    p1c1_start = p1b2_start + D3S2_P1B2_SLICE_COUNT
    p1c1 = suffix[p1c1_start : p1c1_start + D3S2_P1C1_SLICE_COUNT]
    p1c2_start = p1c1_start + D3S2_P1C1_SLICE_COUNT
    p1c2 = suffix[p1c2_start : p1c2_start + D3S2_P1C2_SLICE_COUNT]
    if len(mode25) != D3S2_MODE25_SLICE_COUNT:
        return _fail_check("mode25 slice length mismatch")
    if len(mode26) != D3S2_MODE26_SLICE_COUNT:
        return _fail_check("mode26 slice length mismatch")
    if len(mode24) != D3S2_MODE24_SLICE_COUNT:
        return _fail_check("mode24 slice length mismatch")
    if len(mode23) != D3S2_MODE23_SLICE_COUNT:
        return _fail_check("mode23 slice length mismatch")
    if len(mode22) != D3S2_MODE22_SLICE_COUNT:
        return _fail_check("mode22 slice length mismatch")
    if len(mode21) != D3S2_MODE21_SLICE_COUNT:
        return _fail_check("mode21 slice length mismatch")
    if len(p0a) != D3S2_P0A_SLICE_COUNT:
        return _fail_check("p0a slice length mismatch")
    if len(p0b) != D3S2_P0B_SLICE_COUNT:
        return _fail_check("p0b slice length mismatch")
    if len(p0c) != D3S2_P0C_SLICE_COUNT:
        return _fail_check("p0c slice length mismatch")
    if len(p0d) != D3S2_P0D_SLICE_COUNT:
        return _fail_check("p0d slice length mismatch")
    if len(p1a) != D3S2_P1A_SLICE_COUNT:
        return _fail_check("p1a slice length mismatch")
    if len(p1d) != D3S2_P1D_SLICE_COUNT:
        return _fail_check("p1d slice length mismatch")
    if len(p1d2) != D3S2_P1D2_SLICE_COUNT:
        return _fail_check("p1d2 slice length mismatch")
    if len(p1b1) != D3S2_P1B1_SLICE_COUNT:
        return _fail_check("p1b1 slice length mismatch")
    if len(p1b2) != D3S2_P1B2_SLICE_COUNT:
        return _fail_check("p1b2 slice length mismatch")
    if len(p1c1) != D3S2_P1C1_SLICE_COUNT:
        return _fail_check("p1c1 slice length mismatch")
    if len(p1c2) != D3S2_P1C2_SLICE_COUNT:
        return _fail_check("p1c2 slice length mismatch")

    for j, vec in enumerate(smoke):
        mode = 21 + j
        if int(vec["mode"]) != mode:
            return _fail_check(f"smoke[{j}] mode order pin fail")
        if vec["kind"] != f"mode{mode}_empty_carrier_empty_secondary_ok":
            return _fail_check(f"smoke[{j}] kind pin fail")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if ops[-1] != "finalize":
            return _fail_check(f"{vec['id']}: must end with finalize")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        drive_n = ops.count("d3s2_drive")
        if drive_n != MODE_DRIVE_COUNT[mode]:
            return _fail_check(
                f"{vec['id']}: d3s2_drive count {drive_n} != "
                f"{MODE_DRIVE_COUNT[mode]}"
            )
        if any(int(c.get("mode", mode)) != mode for c in vec["calls"] if "mode" in c):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        exp = vec["expected"]
        if int(exp["phase"]) != PHASE_COMPLETE:
            return _fail_check(f"{vec['id']}: phase must be COMPLETE")
        if int(exp["count_complete_mask"]) != 0:
            return _fail_check(f"{vec['id']}: empty-carrier count_mask must be 0")
        if int(exp["binding_complete_mask"]) != MODE_BIND_MASK[mode]:
            return _fail_check(f"{vec['id']}: binding_complete_mask pin fail")
        if int(exp["iter_open_count"]) != MODE_ITER_OPEN[mode]:
            return _fail_check(f"{vec['id']}: iter_open_count pin fail")
        if int(exp["adopted"]) != 1:
            return _fail_check(f"{vec['id']}: adopted must be 1")
        exp_calls, exp_expected = run_d3s2_empty_carrier_case(
            mode, vec["candidate_binding"], vec["rows"]
        )
        if vec["calls"] != exp_calls:
            return _fail_check(f"{vec['id']}: calls != independent model")
        if vec["expected"] != exp_expected:
            return _fail_check(f"{vec['id']}: expected != independent model")

    # Mode25 slice pins.
    m25_ok = mode25[0]
    m25_bad = mode25[1]
    if m25_ok["kind"] != "mode25_cum_total1_recent_slot1_anchor_ok":
        return _fail_check("mode25[0] kind pin fail")
    if m25_bad["kind"] != "mode25_recent_without_cum_carrier_absent_corrupt":
        return _fail_check("mode25[1] kind pin fail")
    for vec in mode25:
        if int(vec["mode"]) != 25:
            return _fail_check(f"{vec['id']}: mode must be 25")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 25)) != 25 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m25_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m25_ok['id']}: success must end with finalize")
    if int(m25_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m25_ok['id']}: phase must be COMPLETE")
    if int(m25_ok["expected"]["count_complete_mask"]) != MASK_RETRY:
        return _fail_check(f"{m25_ok['id']}: count_complete_mask pin fail")
    if int(m25_ok["expected"]["binding_complete_mask"]) != MASK_RETRY:
        return _fail_check(f"{m25_ok['id']}: binding_complete_mask pin fail")
    if int(m25_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m25_ok['id']}: adopted must be 1")
    if int(m25_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m25_ok['id']}: sticky must be clear")
    try:
        exp_calls, exp_expected = run_d3s2_mode25_cum_total1_success(
            m25_ok["candidate_binding"], m25_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m25_ok['id']}: model reject: {exc}")
    if m25_ok["calls"] != exp_calls:
        return _fail_check(f"{m25_ok['id']}: calls != independent model")
    if m25_ok["expected"] != exp_expected:
        return _fail_check(f"{m25_ok['id']}: expected != independent model")

    if m25_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m25_bad['id']}: fail path must end with abort")
    if int(m25_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m25_bad['id']}: phase must be FAILED")
    if m25_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m25_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m25_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m25_bad['id']}: adopted must be 0")
    if int(m25_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m25_bad['id']}: sticky must be set")
    if m25_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m25_bad['id']}: sticky_primary pin fail")
    if int(m25_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m25_bad['id']}: binding mask must stay 0")
    if int(m25_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m25_bad['id']}: count mask must stay 0")
    try:
        exp_calls, exp_expected = run_d3s2_mode25_recent_without_cum_corrupt(
            m25_bad["candidate_binding"], m25_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m25_bad['id']}: model reject: {exc}")
    if m25_bad["calls"] != exp_calls:
        return _fail_check(f"{m25_bad['id']}: calls != independent model")
    if m25_bad["expected"] != exp_expected:
        return _fail_check(f"{m25_bad['id']}: expected != independent model")

    # Mode26 slice pins.
    m26_ok = mode26[0]
    m26_bad = mode26[1]
    if m26_ok["kind"] != "mode26_es_resume1_mgmt_resume_anchor_ok":
        return _fail_check("mode26[0] kind pin fail")
    if m26_bad["kind"] != "mode26_mgmt_without_es_carrier_absent_corrupt":
        return _fail_check("mode26[1] kind pin fail")
    for vec in mode26:
        if int(vec["mode"]) != 26:
            return _fail_check(f"{vec['id']}: mode must be 26")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 26)) != 26 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m26_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m26_ok['id']}: success must end with finalize")
    if int(m26_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m26_ok['id']}: phase must be COMPLETE")
    if int(m26_ok["expected"]["count_complete_mask"]) != MASK_MANAGEMENT:
        return _fail_check(f"{m26_ok['id']}: count_complete_mask pin fail")
    if int(m26_ok["expected"]["binding_complete_mask"]) != MASK_MANAGEMENT:
        return _fail_check(f"{m26_ok['id']}: binding_complete_mask pin fail")
    if int(m26_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m26_ok['id']}: adopted must be 1")
    if int(m26_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m26_ok['id']}: sticky must be clear")
    if int(m26_ok["expected"]["iter_open_count"]) != 5:
        return _fail_check(f"{m26_ok['id']}: stream success iter_open_count pin")
    # Independent parse of ES carrier in rows: resume=1 discard=0.
    es_rows = [
        r
        for r in m26_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x50
    ]
    if len(es_rows) != 1:
        return _fail_check(f"{m26_ok['id']}: exactly one EVENT_SPOOL row required")
    try:
        es_r, es_d = _parse_es_resume_discard(from_hex(es_rows[0]["value_hex"]))
    except SystemExit as exc:
        return _fail_check(f"{m26_ok['id']}: ES parse fail: {exc}")
    if es_r != 1 or es_d != 0:
        return _fail_check(
            f"{m26_ok['id']}: ES resume/discard must be 1/0, got {es_r}/{es_d}"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode26_es_resume1_success(
            m26_ok["candidate_binding"], m26_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m26_ok['id']}: model reject: {exc}")
    if m26_ok["calls"] != exp_calls:
        return _fail_check(f"{m26_ok['id']}: calls != independent model")
    if m26_ok["expected"] != exp_expected:
        return _fail_check(f"{m26_ok['id']}: expected != independent model")

    if m26_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m26_bad['id']}: fail path must end with abort")
    if int(m26_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m26_bad['id']}: phase must be FAILED")
    if m26_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m26_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m26_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m26_bad['id']}: adopted must be 0")
    if int(m26_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m26_bad['id']}: sticky must be set")
    if m26_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m26_bad['id']}: sticky_primary pin fail")
    if int(m26_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m26_bad['id']}: binding mask must stay 0")
    if int(m26_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m26_bad['id']}: count mask must stay 0")
    # Orphan path must not include EVENT_SPOOL rows.
    es_bad = [
        r
        for r in m26_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x50
    ]
    if es_bad:
        return _fail_check(f"{m26_bad['id']}: EVENT_SPOOL must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode26_mgmt_without_es_corrupt(
            m26_bad["candidate_binding"], m26_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m26_bad['id']}: model reject: {exc}")
    if m26_bad["calls"] != exp_calls:
        return _fail_check(f"{m26_bad['id']}: calls != independent model")
    if m26_bad["expected"] != exp_expected:
        return _fail_check(f"{m26_bad['id']}: expected != independent model")

    # Mode24 slice pins.
    m24_ok = mode24[0]
    m24_bad = mode24[1]
    if m24_ok["kind"] != "mode24_rc_reply1_receipt_delivery_ok":
        return _fail_check("mode24[0] kind pin fail")
    if m24_bad["kind"] != "mode24_rr_without_rc_carrier_absent_corrupt":
        return _fail_check("mode24[1] kind pin fail")
    for vec in mode24:
        if int(vec["mode"]) != 24:
            return _fail_check(f"{vec['id']}: mode must be 24")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 24)) != 24 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m24_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m24_ok['id']}: success must end with finalize")
    if int(m24_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m24_ok['id']}: phase must be COMPLETE")
    if int(m24_ok["expected"]["count_complete_mask"]) != MASK_REPLY:
        return _fail_check(f"{m24_ok['id']}: count_complete_mask pin fail")
    if int(m24_ok["expected"]["binding_complete_mask"]) != MASK_REPLY:
        return _fail_check(f"{m24_ok['id']}: binding_complete_mask pin fail")
    if int(m24_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m24_ok['id']}: adopted must be 1")
    if int(m24_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m24_ok['id']}: sticky must be clear")
    if int(m24_ok["expected"]["iter_open_count"]) != 4:
        return _fail_check(f"{m24_ok['id']}: known-kind success iter_open_count pin")
    # Independent parse: RESULT_CACHE reply_count=1; RR RECEIPT kind=1;
    # delivery raw identity match across RC/RR/DELIVERY.
    rc_rows = [
        r
        for r in m24_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    rr_rows = [
        r
        for r in m24_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x42
    ]
    dlv_rows = [
        r
        for r in m24_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x40
    ]
    if len(rc_rows) != 1 or len(rr_rows) != 1 or len(dlv_rows) != 1:
        return _fail_check(
            f"{m24_ok['id']}: exact one DELIVERY/RESULT_CACHE/REVERSE_REPLY "
            f"required (got dlv={len(dlv_rows)} rc={len(rc_rows)} rr={len(rr_rows)})"
        )
    try:
        rc_count, rc_draw, _ = _parse_rc_reply_count_and_delivery(
            from_hex(rc_rows[0]["value_hex"])
        )
        rr_kind, rr_draw, _ = _parse_rr_kind_and_delivery(
            from_hex(rr_rows[0]["value_hex"])
        )
        dlv_draw, _, _ = _parse_delivery_raw_and_primary(
            from_hex(dlv_rows[0]["value_hex"])
        )
    except (SystemExit, ValueError, struct.error, KeyError) as exc:
        return _fail_check(f"{m24_ok['id']}: Mode24 parse fail: {exc}")
    if rc_count != 1:
        return _fail_check(
            f"{m24_ok['id']}: RESULT_CACHE reply_count must be 1, got {rc_count}"
        )
    if rr_kind != RR_KIND_RECEIPT:
        return _fail_check(
            f"{m24_ok['id']}: REVERSE_REPLY kind must be RECEIPT=1, got {rr_kind}"
        )
    if not (rc_draw == rr_draw == dlv_draw):
        return _fail_check(
            f"{m24_ok['id']}: delivery raw identity mismatch across RC/RR/DELIVERY"
        )
    # FOCUS close invariants mirrored in expected peer_get/mode_applicable.
    if int(m24_ok["expected"]["d3_peer_get_count"]) != 6:
        return _fail_check(f"{m24_ok['id']}: d3_peer_get_count pin fail")
    if int(m24_ok["expected"]["d3_mode_applicable_count"]) != 1:
        return _fail_check(f"{m24_ok['id']}: d3_mode_applicable_count pin fail")
    try:
        exp_calls, exp_expected = run_d3s2_mode24_rc_reply1_success(
            m24_ok["candidate_binding"], m24_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m24_ok['id']}: model reject: {exc}")
    if m24_ok["calls"] != exp_calls:
        return _fail_check(f"{m24_ok['id']}: calls != independent model")
    if m24_ok["expected"] != exp_expected:
        return _fail_check(f"{m24_ok['id']}: expected != independent model")

    if m24_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m24_bad['id']}: fail path must end with abort")
    if int(m24_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m24_bad['id']}: phase must be FAILED")
    if m24_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m24_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m24_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m24_bad['id']}: adopted must be 0")
    if int(m24_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m24_bad['id']}: sticky must be set")
    if m24_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m24_bad['id']}: sticky_primary pin fail")
    if int(m24_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m24_bad['id']}: binding mask must stay 0")
    if int(m24_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m24_bad['id']}: count mask must stay 0")
    # Orphan path must not include RESULT_CACHE rows.
    rc_bad = [
        r
        for r in m24_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    if rc_bad:
        return _fail_check(f"{m24_bad['id']}: RESULT_CACHE must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode24_rr_without_rc_corrupt(
            m24_bad["candidate_binding"], m24_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m24_bad['id']}: model reject: {exc}")
    if m24_bad["calls"] != exp_calls:
        return _fail_check(f"{m24_bad['id']}: calls != independent model")
    if m24_bad["expected"] != exp_expected:
        return _fail_check(f"{m24_bad['id']}: expected != independent model")

    # Mode23 slice pins.
    m23_ok = mode23[0]
    m23_bad = mode23[1]
    if m23_ok["kind"] != "mode23_tx_state_slots_L_equation_anchor_ok":
        return _fail_check("mode23[0] kind pin fail")
    if m23_bad["kind"] != "mode23_evidence_without_state_carrier_absent_corrupt":
        return _fail_check("mode23[1] kind pin fail")
    for vec in mode23:
        if int(vec["mode"]) != 23:
            return _fail_check(f"{vec['id']}: mode must be 23")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 23)) != 23 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m23_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m23_ok['id']}: success must end with finalize")
    if int(m23_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m23_ok['id']}: phase must be COMPLETE")
    if int(m23_ok["expected"]["count_complete_mask"]) != MASK_EVIDENCE:
        return _fail_check(f"{m23_ok['id']}: count_complete_mask pin fail")
    if int(m23_ok["expected"]["binding_complete_mask"]) != MASK_EVIDENCE:
        return _fail_check(f"{m23_ok['id']}: binding_complete_mask pin fail")
    if int(m23_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m23_ok['id']}: adopted must be 1")
    if int(m23_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m23_ok['id']}: sticky must be clear")
    if int(m23_ok["expected"]["iter_open_count"]) != 4:
        return _fail_check(f"{m23_ok['id']}: known-slot success iter_open_count pin")
    # Independent parse: STATE present; SUMMARY equation; slots 0..L.
    L = int(m23_ok["candidate_binding"]["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        return _fail_check(f"{m23_ok['id']}: accepted L pin fail, got {L}")
    state_rows = [
        r
        for r in m23_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    anchor_rows = [
        r
        for r in m23_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x20
    ]
    ev_rows = [
        r
        for r in m23_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x32
    ]
    if len(state_rows) != 1 or len(anchor_rows) != 1 or len(ev_rows) != L + 1:
        return _fail_check(
            f"{m23_ok['id']}: exact one STATE/ANCHOR and L+1 EVIDENCE "
            f"required (got state={len(state_rows)} anchor={len(anchor_rows)} "
            f"ev={len(ev_rows)})"
        )
    # EVIDENCE rows must be complete-key lex sorted (SHA256_COMPOSITE scatter).
    ev_keys = [from_hex(r["key_hex"]) for r in ev_rows]
    if ev_keys != sorted(ev_keys):
        return _fail_check(f"{m23_ok['id']}: EVIDENCE rows not key-lex sorted")
    try:
        parsed = [_parse_tx_evidence_cell(from_hex(r["value_hex"])) for r in ev_rows]
    except (SystemExit, ValueError, struct.error, KeyError, IndexError) as exc:
        return _fail_check(f"{m23_ok['id']}: Mode23 EV parse fail: {exc}")
    by_slot = {p[2]: p for p in parsed}
    if set(by_slot.keys()) != set(range(L + 1)):
        return _fail_check(f"{m23_ok['id']}: EVIDENCE slots must be exact 0..L")
    s0 = by_slot[0]
    if s0[0] != EV_CELL_KIND_SUMMARY or s0[1] != EV_CELL_STATE_MATERIALIZED:
        return _fail_check(f"{m23_ok['id']}: slot0 must be SUMMARY MATERIALIZED")
    valid, overflow, late_c, late_m = s0[4], s0[5], s0[6], s0[7]
    if (valid, overflow, late_c, late_m) != (2, 1, 1, 1):
        return _fail_check(
            f"{m23_ok['id']}: SUMMARY counters must be 2/1/1/1, got "
            f"{valid}/{overflow}/{late_c}/{late_m}"
        )
    m_obs = 0
    late_obs = 0
    for slot in range(1, L + 1):
        ck, cs, _sl, _ow, _v, _o, _lc, lm = by_slot[slot]
        if ck != EV_CELL_KIND_RAW:
            return _fail_check(f"{m23_ok['id']}: slot{slot} must be RAW")
        if cs == EV_CELL_STATE_MATERIALIZED:
            m_obs += 1
            if lm == 1:
                late_obs += 1
        elif cs != EV_CELL_STATE_UNUSED:
            return _fail_check(f"{m23_ok['id']}: slot{slot} bad RAW state")
    if m_obs != 1 or late_obs != 1:
        return _fail_check(
            f"{m23_ok['id']}: observed M/late must be 1/1, got {m_obs}/{late_obs}"
        )
    if valid != m_obs + overflow:
        return _fail_check(f"{m23_ok['id']}: equation valid != M + overflow")
    if not (late_obs <= late_c <= valid and overflow <= valid):
        return _fail_check(f"{m23_ok['id']}: late/overflow coherence fail")
    # FOCUS (L+1) + BIND 2*(L+1)
    if int(m23_ok["expected"]["d3_peer_get_count"]) != (L + 1) + 2 * (L + 1):
        return _fail_check(f"{m23_ok['id']}: d3_peer_get_count pin fail")
    if int(m23_ok["expected"]["d3_mode_applicable_count"]) != L + 1:
        return _fail_check(f"{m23_ok['id']}: d3_mode_applicable_count pin fail")
    try:
        exp_calls, exp_expected = run_d3s2_mode23_tx_state_slots_equation_success(
            m23_ok["candidate_binding"], m23_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_ok['id']}: model reject: {exc}")
    if m23_ok["calls"] != exp_calls:
        return _fail_check(f"{m23_ok['id']}: calls != independent model")
    if m23_ok["expected"] != exp_expected:
        return _fail_check(f"{m23_ok['id']}: expected != independent model")

    if m23_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m23_bad['id']}: fail path must end with abort")
    if int(m23_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m23_bad['id']}: phase must be FAILED")
    if m23_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m23_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m23_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m23_bad['id']}: adopted must be 0")
    if int(m23_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m23_bad['id']}: sticky must be set")
    if m23_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m23_bad['id']}: sticky_primary pin fail")
    if int(m23_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m23_bad['id']}: binding mask must stay 0")
    if int(m23_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m23_bad['id']}: count mask must stay 0")
    # Orphan path must not include TRANSACTION_STATE rows.
    state_bad = [
        r
        for r in m23_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    if state_bad:
        return _fail_check(f"{m23_bad['id']}: TRANSACTION_STATE must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode23_evidence_without_state_corrupt(
            m23_bad["candidate_binding"], m23_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_bad['id']}: model reject: {exc}")
    if m23_bad["calls"] != exp_calls:
        return _fail_check(f"{m23_bad['id']}: calls != independent model")
    if m23_bad["expected"] != exp_expected:
        return _fail_check(f"{m23_bad['id']}: expected != independent model")


    # Mode22 slice pins.
    m22_ok = mode22[0]
    m22_bad = mode22[1]
    if m22_ok["kind"] != "mode22_rc_app1_dlv_attempt_delivery_ok":
        return _fail_check("mode22[0] kind pin fail")
    if m22_bad["kind"] != "mode22_att_without_rc_carrier_absent_corrupt":
        return _fail_check("mode22[1] kind pin fail")
    for vec in mode22:
        if int(vec["mode"]) != 22:
            return _fail_check(f"{vec['id']}: mode must be 22")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 22)) != 22 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")
        # Mode22 must never run FOCUS_INDEX / BIND_INDEX (count/binding mask
        # has ATTEMPT bit only; INDEX bit never set).
        if int(vec["expected"].get("count_complete_mask", 0)) & MASK_INDEX:
            return _fail_check(f"{vec['id']}: INDEX count bit must stay 0")
        if int(vec["expected"].get("binding_complete_mask", 0)) & MASK_INDEX:
            return _fail_check(f"{vec['id']}: INDEX binding bit must stay 0")

    if m22_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m22_ok['id']}: success must end with finalize")
    if int(m22_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m22_ok['id']}: phase must be COMPLETE")
    if int(m22_ok["expected"]["count_complete_mask"]) != MASK_ATTEMPT:
        return _fail_check(f"{m22_ok['id']}: count_complete_mask pin fail")
    if int(m22_ok["expected"]["binding_complete_mask"]) != MASK_ATTEMPT:
        return _fail_check(f"{m22_ok['id']}: binding_complete_mask pin fail")
    if int(m22_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m22_ok['id']}: adopted must be 1")
    if int(m22_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m22_ok['id']}: sticky must be clear")
    if int(m22_ok["expected"]["iter_open_count"]) != 5:
        return _fail_check(f"{m22_ok['id']}: stream success iter_open_count pin")
    # Independent parse: RC app=1; ATT DELIVERY-owned COMMAND; raw match;
    # no ATTEMPT_ID_INDEX rows (INDEX expect 0 via BIND ABSENT only).
    rc_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    att_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x31
    ]
    dlv_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x40
    ]
    aii_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x34
    ]
    if len(rc_rows) != 1 or len(att_rows) != 1 or len(dlv_rows) != 1:
        return _fail_check(
            f"{m22_ok['id']}: exact one DELIVERY/RESULT_CACHE/ATTEMPT "
            f"required (got dlv={len(dlv_rows)} rc={len(rc_rows)} "
            f"att={len(att_rows)})"
        )
    if aii_rows:
        return _fail_check(f"{m22_ok['id']}: ATTEMPT_ID_INDEX must be absent")
    # ATTEMPT complete-key lex order among all rows.
    all_keys = [from_hex(r["key_hex"]) for r in m22_ok["rows"]]
    if all_keys != sorted(all_keys):
        return _fail_check(f"{m22_ok['id']}: rows not complete-key lex sorted")
    try:
        app_n, rc_draw, _ = _parse_rc_app_attempt_and_delivery(
            from_hex(rc_rows[0]["value_hex"])
        )
        att_okind, att_oraw, _aid, _atxn, att_kind, att_pkd, _apvd = (
            _parse_attempt_dlv(from_hex(att_rows[0]["value_hex"]))
        )
        dlv_draw, _, _ = _parse_delivery_raw_and_primary(
            from_hex(dlv_rows[0]["value_hex"])
        )
    except (SystemExit, ValueError, struct.error, KeyError, IndexError) as exc:
        return _fail_check(f"{m22_ok['id']}: Mode22 parse fail: {exc}")
    if app_n != 1:
        return _fail_check(
            f"{m22_ok['id']}: RESULT_CACHE application_attempt_count must "
            f"be 1, got {app_n}"
        )
    if att_okind != ATT_OWNER_KIND_DELIVERY or att_kind != ATT_KIND_COMMAND:
        return _fail_check(
            f"{m22_ok['id']}: ATTEMPT must be DELIVERY-owned COMMAND"
        )
    if not (rc_draw == att_oraw == dlv_draw):
        return _fail_check(
            f"{m22_ok['id']}: delivery raw identity mismatch across "
            "RC/ATT/DELIVERY"
        )
    if att_pkd != _d3s1.key_digest(from_hex(dlv_rows[0]["key_hex"])):
        return _fail_check(
            f"{m22_ok['id']}: ATT primary_key_digest != KEY_DIGEST(DELIVERY)"
        )
    # SELECT setup 2 + BIND 3
    if int(m22_ok["expected"]["d3_peer_get_count"]) != 5:
        return _fail_check(f"{m22_ok['id']}: d3_peer_get_count pin fail")
    if int(m22_ok["expected"]["d3_mode_applicable_count"]) != 1:
        return _fail_check(f"{m22_ok['id']}: d3_mode_applicable_count pin fail")
    # Port-trace gets = 17 profile (begin) + 2 SELECT setup + 3 BIND.
    pt = m22_ok["expected"]["port_trace"]
    if pt.count("get") != 17 + 5:
        return _fail_check(
            f"{m22_ok['id']}: port_trace get count must be 22 "
            f"(17 profile + 5 peer), got {pt.count('get')}"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode22_rc_app1_attempt_success(
            m22_ok["candidate_binding"], m22_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_ok['id']}: model reject: {exc}")
    if m22_ok["calls"] != exp_calls:
        return _fail_check(f"{m22_ok['id']}: calls != independent model")
    if m22_ok["expected"] != exp_expected:
        return _fail_check(f"{m22_ok['id']}: expected != independent model")

    if m22_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m22_bad['id']}: fail path must end with abort")
    if int(m22_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m22_bad['id']}: phase must be FAILED")
    if m22_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m22_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m22_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m22_bad['id']}: adopted must be 0")
    if int(m22_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m22_bad['id']}: sticky must be set")
    if m22_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m22_bad['id']}: sticky_primary pin fail")
    if int(m22_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m22_bad['id']}: binding mask must stay 0")
    if int(m22_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m22_bad['id']}: count mask must stay 0")
    if int(m22_bad["expected"]["d3_peer_get_count"]) != 1:
        return _fail_check(
            f"{m22_bad['id']}: orphan d3_peer_get_count must be 1 "
            "(carrier only; primary/INDEX must not run)"
        )
    # Orphan path must not include RESULT_CACHE rows.
    rc_bad = [
        r
        for r in m22_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    if rc_bad:
        return _fail_check(f"{m22_bad['id']}: RESULT_CACHE must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode22_att_without_rc_corrupt(
            m22_bad["candidate_binding"], m22_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_bad['id']}: model reject: {exc}")
    if m22_bad["calls"] != exp_calls:
        return _fail_check(f"{m22_bad['id']}: calls != independent model")
    if m22_bad["expected"] != exp_expected:
        return _fail_check(f"{m22_bad['id']}: expected != independent model")


    # Mode21 slice pins.
    m21_ok = mode21[0]
    m21_bad = mode21[1]
    if m21_ok["kind"] != "mode21_state_cum1_att_tx_aii_anchor_ok":
        return _fail_check("mode21[0] kind pin fail")
    if m21_bad["kind"] != "mode21_att_without_aii_index_pair_absent_corrupt":
        return _fail_check("mode21[1] kind pin fail")
    for vec in mode21:
        if int(vec["mode"]) != 21:
            return _fail_check(f"{vec['id']}: mode must be 21")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 21)) != 21 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")
        # Mode21 requires both ATTEMPT and INDEX count/binding bits when closed.
        if vec is m21_ok:
            need = MASK_ATTEMPT | MASK_INDEX
            if int(vec["expected"].get("count_complete_mask", 0)) != need:
                return _fail_check(f"{vec['id']}: count mask must be bit0|bit1")
            if int(vec["expected"].get("binding_complete_mask", 0)) != need:
                return _fail_check(f"{vec['id']}: binding mask must be bit0|bit1")

    if m21_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m21_ok['id']}: success must end with finalize")
    if int(m21_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m21_ok['id']}: phase must be COMPLETE")
    if int(m21_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m21_ok['id']}: adopted must be 1")
    if int(m21_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m21_ok['id']}: sticky must be clear")
    if int(m21_ok["expected"]["iter_open_count"]) != 7:
        return _fail_check(f"{m21_ok['id']}: stream success iter_open_count pin")
    # Independent parse: STATE cum=1; ATT TX-owned COMMAND; AII pair bijection.
    state_rows = [
        r
        for r in m21_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    att_rows = [
        r
        for r in m21_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x31
    ]
    aii_rows = [
        r
        for r in m21_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x34
    ]
    anc_rows = [
        r
        for r in m21_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x20
    ]
    cp_ok_rows = [
        r
        for r in m21_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    ]
    if (
        len(state_rows) != 1
        or len(att_rows) != 1
        or len(aii_rows) != 1
        or len(anc_rows) != 1
    ):
        return _fail_check(
            f"{m21_ok['id']}: exact one ANCHOR/STATE/ATTEMPT/AII required"
        )
    if cp_ok_rows:
        return _fail_check(
            f"{m21_ok['id']}: ordinary path must not include CLEANUP_PLAN"
        )
    all_keys = [from_hex(r["key_hex"]) for r in m21_ok["rows"]]
    if all_keys != sorted(all_keys):
        return _fail_check(f"{m21_ok['id']}: rows not complete-key lex sorted")
    try:
        cum, state_txn = _parse_state_cum_and_txn(
            from_hex(state_rows[0]["value_hex"])
        )
        att_okind, att_oraw, att_id, att_txn, att_kind, att_pkd, _apvd = (
            _parse_attempt_tx(from_hex(att_rows[0]["value_hex"]))
        )
        aii_id, aii_txn, aii_kind, aii_rkd, _aipvd = _parse_attempt_id_index(
            from_hex(aii_rows[0]["value_hex"])
        )
    except (SystemExit, ValueError, struct.error, KeyError, IndexError) as exc:
        return _fail_check(f"{m21_ok['id']}: Mode21 parse fail: {exc}")
    if cum != 1:
        return _fail_check(
            f"{m21_ok['id']}: STATE cumulative_attempts must be 1, got {cum}"
        )
    if att_okind != ATT_OWNER_KIND_TRANSACTION or att_kind != ATT_KIND_COMMAND:
        return _fail_check(
            f"{m21_ok['id']}: ATTEMPT must be TRANSACTION-owned COMMAND"
        )
    if not (att_oraw == att_txn == state_txn == aii_txn and att_id == aii_id):
        return _fail_check(
            f"{m21_ok['id']}: attempt_id/txn identity mismatch across "
            "STATE/ATT/AII"
        )
    if aii_kind != ATT_KIND_COMMAND:
        return _fail_check(f"{m21_ok['id']}: AII attempt_kind must be COMMAND")
    if att_pkd != _d3s1.key_digest(from_hex(anc_rows[0]["key_hex"])):
        return _fail_check(
            f"{m21_ok['id']}: ATT primary_key_digest != KEY_DIGEST(ANCHOR)"
        )
    if aii_rkd != _d3s1.key_digest(from_hex(att_rows[0]["key_hex"])):
        return _fail_check(
            f"{m21_ok['id']}: AII record_kd != KEY_DIGEST(complete ATTEMPT key)"
        )
    # SELECT setup 2 + BIND_ATTEMPT 3 + BIND_INDEX 2 = 7; no STATE re-get on INDEX
    if int(m21_ok["expected"]["d3_peer_get_count"]) != 7:
        return _fail_check(f"{m21_ok['id']}: d3_peer_get_count pin fail")
    if int(m21_ok["expected"]["d3_mode_applicable_count"]) != 2:
        return _fail_check(f"{m21_ok['id']}: d3_mode_applicable_count pin fail")
    pt = m21_ok["expected"]["port_trace"]
    if pt.count("get") != 17 + 7:
        return _fail_check(
            f"{m21_ok['id']}: port_trace get count must be 24 "
            f"(17 profile + 7 peer), got {pt.count('get')}"
        )
    # P0-D / case15: BIND_INDEX has no STATE companion re-get.
    # Independent of new fields: pin the last BIND open segment has exact 2
    # peer gets (ANCHOR + ATTEMPT pair). A third get would mean illegal STATE
    # companion or unbounded pair budget.
    open_idxs_m21 = [i for i, t in enumerate(pt) if t == "iter_open:prefix0"]
    if len(open_idxs_m21) != 7:
        return _fail_check(
            f"{m21_ok['id']}: success port_trace must have 7 iter_open, got "
            f"{len(open_idxs_m21)}"
        )
    # opens: 0 baseline, 1 SELECT, 2 FOCUS_ATT, 3 FOCUS_IDX, 4 SELECT empty,
    # 5 BIND_ATTEMPT, 6 BIND_INDEX
    bind_att_seg = pt[open_idxs_m21[5] : open_idxs_m21[6]]
    bind_idx_seg = pt[open_idxs_m21[6] :]
    if bind_att_seg.count("get") != 3:
        return _fail_check(
            f"{m21_ok['id']}: BIND_ATTEMPT segment must have exact 3 gets "
            f"(carrier+primary+pair), got {bind_att_seg.count('get')}"
        )
    if bind_idx_seg.count("get") != 2:
        return _fail_check(
            f"{m21_ok['id']}: BIND_INDEX segment must have exact 2 gets "
            f"(ANCHOR primary + ATTEMPT pair; no STATE companion), got "
            f"{bind_idx_seg.count('get')}"
        )
    # Exact order pin: BIND_INDEX secondary then get,get (no third get).
    try:
        aii_i = bind_idx_seg.index("iter_next")  # first domain after profile
        # walk: 17 profile nexts then ANCHOR STATE ATT AII-secondary
        # Find the three consecutive gets after AII secondary by scanning
        # the last get-run of length 2 before iter_close.
        get_runs = 0
        i_seg = 0
        last_two_gets_at = -1
        while i_seg < len(bind_idx_seg):
            if (
                i_seg + 1 < len(bind_idx_seg)
                and bind_idx_seg[i_seg] == "get"
                and bind_idx_seg[i_seg + 1] == "get"
            ):
                # reject length-3 get run
                if (
                    i_seg + 2 < len(bind_idx_seg)
                    and bind_idx_seg[i_seg + 2] == "get"
                ):
                    return _fail_check(
                        f"{m21_ok['id']}: BIND_INDEX must not have 3 consecutive "
                        "gets (STATE companion forbidden)"
                    )
                last_two_gets_at = i_seg
                get_runs += 1
                i_seg += 2
                continue
            i_seg += 1
        if get_runs != 1 or last_two_gets_at < 0:
            return _fail_check(
                f"{m21_ok['id']}: BIND_INDEX must have exactly one get,get run"
            )
        _ = aii_i
    except ValueError:
        return _fail_check(f"{m21_ok['id']}: BIND_INDEX segment parse fail")
    try:
        exp_calls, exp_expected = run_d3s2_mode21_state_cum1_att_aii_success(
            m21_ok["candidate_binding"], m21_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_ok['id']}: model reject: {exc}")
    if m21_ok["calls"] != exp_calls:
        return _fail_check(f"{m21_ok['id']}: calls != independent model")
    if m21_ok["expected"] != exp_expected:
        return _fail_check(f"{m21_ok['id']}: expected != independent model")

    if m21_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m21_bad['id']}: fail path must end with abort")
    if int(m21_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m21_bad['id']}: phase must be FAILED")
    if m21_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m21_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m21_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m21_bad['id']}: adopted must be 0")
    if int(m21_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m21_bad['id']}: sticky must be set")
    if m21_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m21_bad['id']}: sticky_primary pin fail")
    if int(m21_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m21_bad['id']}: binding mask must stay 0")
    # cleanup_skip FOCUS still sets both count bits before BIND pair fail
    if int(m21_bad["expected"]["count_complete_mask"]) != (
        MASK_ATTEMPT | MASK_INDEX
    ):
        return _fail_check(
            f"{m21_bad['id']}: count mask must be bit0|bit1 after cleanup_skip"
        )
    if int(m21_bad["expected"]["d3_peer_get_count"]) != 5:
        return _fail_check(
            f"{m21_bad['id']}: pair-absent d3_peer_get_count must be 5 "
            "(setup 2 + BIND carrier/primary/INDEX ABSENT; BIND_INDEX must not run)"
        )
    aii_bad = [
        r
        for r in m21_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x34
    ]
    if aii_bad:
        return _fail_check(f"{m21_bad['id']}: ATTEMPT_ID_INDEX must be absent")
    cp_bad = [
        r
        for r in m21_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    ]
    if len(cp_bad) != 1:
        return _fail_check(
            f"{m21_bad['id']}: CLEANUP_PLAN must be PRESENT for constructible path"
        )
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode21_att_without_aii_index_pair_absent_corrupt(
                m21_bad["candidate_binding"], m21_bad["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_bad['id']}: model reject: {exc}")
    if m21_bad["calls"] != exp_calls:
        return _fail_check(f"{m21_bad['id']}: calls != independent model")
    if m21_bad["expected"] != exp_expected:
        return _fail_check(f"{m21_bad['id']}: expected != independent model")

    # ---- P0-A multi-owner Mode25 (§18.13.15 cases 2/6) ----
    p0a_ok = p0a[0]
    if p0a_ok["kind"] != "mode25_two_owner_sha_interleave_dual_carrier_ok":
        return _fail_check("p0a[0] kind pin fail")
    if int(p0a_ok["mode"]) != 25:
        return _fail_check(f"{p0a_ok['id']}: mode must be 25")
    if p0a_ok.get("ownership") != OWNERSHIP_P0A:
        return _fail_check(f"{p0a_ok['id']}: ownership pin fail")
    if int(p0a_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{p0a_ok['id']}: phase must be COMPLETE")
    if int(p0a_ok["expected"]["binding_complete_mask"]) != MASK_RETRY:
        return _fail_check(f"{p0a_ok['id']}: binding mask pin fail")
    if int(p0a_ok["expected"]["count_complete_mask"]) != MASK_RETRY:
        return _fail_check(f"{p0a_ok['id']}: count mask pin fail")
    if int(p0a_ok["expected"]["d3_peer_get_count"]) != 16:
        return _fail_check(f"{p0a_ok['id']}: d3_peer_get_count must be 16")
    if int(p0a_ok["expected"]["d3_mode_applicable_count"]) != 4:
        return _fail_check(f"{p0a_ok['id']}: d3_mode_applicable_count must be 4")
    if int(p0a_ok["expected"]["current_domain_key_count"]) != 6:
        return _fail_check(f"{p0a_ok['id']}: current_domain_key_count must be 6")
    if int(p0a_ok["expected"]["ok_row_count"]) != 23:
        return _fail_check(f"{p0a_ok['id']}: ok_row_count must be 23")
    if int(p0a_ok["expected"]["iter_open_count"]) != 5:
        return _fail_check(f"{p0a_ok['id']}: iter_open_count must be 5")
    pt_p0a = p0a_ok["expected"]["port_trace"]
    if pt_p0a.count("get") != 17 + 16:
        return _fail_check(
            f"{p0a_ok['id']}: port_trace get count must be 33 "
            f"(17 profile + 16 peer), got {pt_p0a.count('get')}"
        )
    # Exactly two FOCUS matrix segments of 5 consecutive gets (carrier no-skip).
    focus_matrix_runs = 0
    i_pt = 0
    while i_pt + 4 < len(pt_p0a):
        if all(pt_p0a[i_pt + k] == "get" for k in range(5)):
            # Count only after an iter walk (not baseline profile 17 gets).
            if i_pt > 0 and pt_p0a[i_pt - 1] == "iter_next":
                focus_matrix_runs += 1
                i_pt += 5
                continue
        i_pt += 1
    if focus_matrix_runs != 2:
        return _fail_check(
            f"{p0a_ok['id']}: expected 2 FOCUS matrix runs of 5 gets, "
            f"got {focus_matrix_runs}"
        )
    # Body-parse RETRY owner order: must be non-contiguous ABAB (not row count).
    retry_owner_seq: List[str] = []
    retry_kind_seq: List[int] = []
    for r in p0a_ok["rows"]:
        key = from_hex(r["key_hex"])
        if len(key) < 10 or key[8] != 6 or key[9] != 0x51:
            continue
        tx, kind, _slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if tx == MODE25_MULTI_TX_A:
            retry_owner_seq.append("A")
        elif tx == MODE25_MULTI_TX_B:
            retry_owner_seq.append("B")
        else:
            return _fail_check(
                f"{p0a_ok['id']}: unexpected RETRY tx {tx.hex()}"
            )
        retry_kind_seq.append(int(kind))
    if len(retry_owner_seq) != 4:
        return _fail_check(
            f"{p0a_ok['id']}: body-parse expects 4 RETRY rows, "
            f"got {len(retry_owner_seq)}"
        )
    owner_s = "".join(retry_owner_seq)
    if owner_s != MODE25_MULTI_OWNER_ORDER_PIN:
        return _fail_check(
            f"{p0a_ok['id']}: owner order {owner_s!r} != pin "
            f"{MODE25_MULTI_OWNER_ORDER_PIN!r}"
        )
    if tuple(retry_kind_seq) != MODE25_MULTI_KIND_ORDER_PIN:
        return _fail_check(
            f"{p0a_ok['id']}: kind order {tuple(retry_kind_seq)!r} != pin"
        )
    if not _owners_are_noncontiguous(owner_s):
        return _fail_check(
            f"{p0a_ok['id']}: owners form contiguous runs (interleave fail)"
        )
    # Contiguous AA BB would fail the above; also reject if owners are runs.
    if owner_s in ("AABB", "BBAA"):
        return _fail_check(f"{p0a_ok['id']}: contiguous-owner order forbidden")
    # Carrier CUM keys must be two and ordered A then B.
    cum_txs: List[bytes] = []
    for r in p0a_ok["rows"]:
        key = from_hex(r["key_hex"])
        if len(key) < 10 or key[8] != 6 or key[9] != 0x51:
            continue
        tx, kind, slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if kind == RS_KIND_CUMULATIVE and slot == 0:
            cum_txs.append(tx)
    if cum_txs != [MODE25_MULTI_TX_A, MODE25_MULTI_TX_B]:
        return _fail_check(
            f"{p0a_ok['id']}: CUM carrier TX order must be A then B"
        )
    # Bounded TX pair pin self-check.
    try:
        sel_a, sel_b = _select_mode25_multi_owner_tx_pair()
    except SystemExit as exc:
        return _fail_check(f"{p0a_ok['id']}: TX pair select fail: {exc}")
    if sel_a != MODE25_MULTI_TX_A or sel_b != MODE25_MULTI_TX_B:
        return _fail_check(f"{p0a_ok['id']}: TX pair pin mismatch")
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode25_two_owner_sha_interleave_dual_carrier_success(
                p0a_ok["candidate_binding"], p0a_ok["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{p0a_ok['id']}: model reject: {exc}")
    if p0a_ok["calls"] != exp_calls:
        return _fail_check(f"{p0a_ok['id']}: calls != independent model")
    if p0a_ok["expected"] != exp_expected:
        return _fail_check(f"{p0a_ok['id']}: expected != independent model")

    # ---- P0-B Mode26 budget mid-focus resume (§18.13.15 case13) ----
    p0b_ok = p0b[0]
    if p0b_ok["kind"] != "mode26_es_mgmt_budget_mid_focus_resume_ok":
        return _fail_check("p0b[0] kind pin fail")
    if int(p0b_ok["mode"]) != 26:
        return _fail_check(f"{p0b_ok['id']}: mode must be 26")
    if p0b_ok.get("ownership") != OWNERSHIP_P0B:
        return _fail_check(f"{p0b_ok['id']}: ownership pin fail")
    if int(p0b_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{p0b_ok['id']}: phase must be COMPLETE")
    if int(p0b_ok["expected"]["count_complete_mask"]) != MASK_MANAGEMENT:
        return _fail_check(f"{p0b_ok['id']}: count mask pin fail")
    if int(p0b_ok["expected"]["binding_complete_mask"]) != MASK_MANAGEMENT:
        return _fail_check(f"{p0b_ok['id']}: binding mask pin fail")
    if int(p0b_ok["expected"]["d3_peer_get_count"]) != 2:
        return _fail_check(f"{p0b_ok['id']}: d3_peer_get_count must be 2")
    if int(p0b_ok["expected"]["iter_open_count"]) != 5:
        return _fail_check(f"{p0b_ok['id']}: iter_open_count must be 5")
    if int(p0b_ok["expected"]["ok_row_count"]) != 20:
        return _fail_check(f"{p0b_ok['id']}: ok_row_count must be 20")
    # Independent OK-row classification must re-derive focus budget (not magic).
    n_ok_re = _fixture_ok_row_count(p0b_ok["rows"])
    if n_ok_re != 20:
        return _fail_check(f"{p0b_ok['id']}: OK-row reclassify must be 20")
    cp_calls = [
        c
        for c in p0b_ok["calls"]
        if int(c.get("has_checkpoint", 0)) == 1
    ]
    if len(cp_calls) != 1:
        return _fail_check(f"{p0b_ok['id']}: exactly one checkpoint call required")
    cp = cp_calls[0]
    if int(cp["row_budget"]) != n_ok_re:
        return _fail_check(
            f"{p0b_ok['id']}: focus row_budget {cp['row_budget']} != "
            f"derived n_ok {n_ok_re}"
        )
    if int(cp["cp_phase"]) != PHASE_FOCUS_MANAGEMENT:
        return _fail_check(f"{p0b_ok['id']}: cp_phase must be FOCUS_MANAGEMENT")
    if int(cp["cp_focus_live"]) != 1:
        return _fail_check(f"{p0b_ok['id']}: cp_focus_live must be 1")
    if int(cp["cp_observed_a"]) != 1:
        return _fail_check(f"{p0b_ok['id']}: cp_observed_a must be 1")
    if int(cp["cp_observed_b"]) != 0 or int(cp["cp_observed_c"]) != 0:
        return _fail_check(f"{p0b_ok['id']}: non-a observed lanes must be 0")
    if int(cp["cp_count_complete_mask"]) != 0:
        return _fail_check(f"{p0b_ok['id']}: count_complete_mask must be 0 at B5")
    if int(cp["cp_binding_complete_mask"]) != 0:
        return _fail_check(f"{p0b_ok['id']}: binding_complete_mask must be 0 at B5")
    if (int(cp["cp_flags"]) & FLAG_COMPLETE_READY) != 0:
        return _fail_check(f"{p0b_ok['id']}: COMPLETE_READY must be 0 at B5")
    if (int(cp["cp_flags"]) & FLAG_FOCUS_LIVE) == 0:
        return _fail_check(f"{p0b_ok['id']}: FOCUS_LIVE must be set at B5")
    if int(cp["cp_pass_kind"]) != PASS_INTERNAL:
        return _fail_check(f"{p0b_ok['id']}: pass_kind must be PASS_INTERNAL")
    if int(cp["cp_cleanup_skip"]) != 0:
        return _fail_check(f"{p0b_ok['id']}: cleanup_skip must be 0")
    if int(cp["cp_last_carrier_key_len"]) <= 0:
        return _fail_check(f"{p0b_ok['id']}: last_carrier_key_len must be > 0")
    if int(cp["cp_begin_calls"]) != 1:
        return _fail_check(f"{p0b_ok['id']}: begin_calls must be 1 (not B11)")
    if int(cp["cp_iter_open_calls"]) != 3:
        return _fail_check(f"{p0b_ok['id']}: iter_open_calls at B5 must be 3")
    if int(cp["cp_iter_close_calls"]) != 2:
        return _fail_check(f"{p0b_ok['id']}: iter_close_calls at B5 must be 2")
    # Port-trace B5 boundary: no close/open/begin between last FOCUS OK and NF.
    pt = p0b_ok["expected"]["port_trace"]
    if pt.count("begin:READ_ONLY") != 1:
        return _fail_check(f"{p0b_ok['id']}: exactly one begin in port_trace")
    # Locate third open (FOCUS) then n_ok consecutive next, then NF next.
    open_idxs = [i for i, t in enumerate(pt) if t == "iter_open:prefix0"]
    if len(open_idxs) != 5:
        return _fail_check(
            f"{p0b_ok['id']}: port_trace iter_open count must be 5, got {len(open_idxs)}"
        )
    focus_open = open_idxs[2]
    focus_ok_end = focus_open + 1 + n_ok_re
    if pt[focus_open + 1 : focus_ok_end] != ["iter_next"] * n_ok_re:
        return _fail_check(f"{p0b_ok['id']}: FOCUS OK segment mismatch")
    if pt[focus_ok_end] != "iter_next":
        return _fail_check(f"{p0b_ok['id']}: NOT_FOUND must follow budget stop")
    if any(
        x in ("iter_close", "iter_open:prefix0", "begin:READ_ONLY")
        for x in pt[focus_ok_end - 1 : focus_ok_end + 1]
    ):
        return _fail_check(
            f"{p0b_ok['id']}: B5 boundary must not insert close/open/begin"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode26_es_mgmt_budget_mid_focus_resume(
            p0b_ok["candidate_binding"], p0b_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{p0b_ok['id']}: model reject: {exc}")
    if p0b_ok["calls"] != exp_calls:
        return _fail_check(f"{p0b_ok['id']}: calls != independent model")
    if p0b_ok["expected"] != exp_expected:
        return _fail_check(f"{p0b_ok['id']}: expected != independent model")

    # ---- P0-C Mode25 BIND Port terminal note 0 (§18.13.15 #7/#11) ----
    p0c_vec = p0c[0]
    if p0c_vec["kind"] != "mode25_bind_exact_get_port_failure_note0":
        return _fail_check("p0c[0] kind pin fail")
    if int(p0c_vec["mode"]) != 25:
        return _fail_check(f"{p0c_vec['id']}: mode must be 25")
    if p0c_vec.get("ownership") != OWNERSHIP_P0C:
        return _fail_check(f"{p0c_vec['id']}: ownership pin fail")
    if p0c_vec["expected"].get("final_status") != "STORAGE":
        return _fail_check(f"{p0c_vec['id']}: final_status must be STORAGE")
    if p0c_vec["expected"].get("sticky_primary") != "STORAGE":
        return _fail_check(f"{p0c_vec['id']}: sticky must be STORAGE (Port path)")
    if int(p0c_vec["expected"].get("note_count", -1)) != 0:
        return _fail_check(f"{p0c_vec['id']}: note_count must be 0")
    if int(p0c_vec["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{p0c_vec['id']}: phase must be FAILED")
    if int(p0c_vec["expected"]["count_complete_mask"]) != MASK_RETRY:
        return _fail_check(
            f"{p0c_vec['id']}: count mask must retain FOCUS close (MASK_RETRY)"
        )
    if int(p0c_vec["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{p0c_vec['id']}: binding mask must be 0")
    if int(p0c_vec["expected"]["d3_peer_get_count"]) != 6:
        return _fail_check(f"{p0c_vec['id']}: d3_peer_get_count must be 6")
    faults = p0c_vec.get("faults") or []
    if len(faults) != 1 or faults[0].get("op") != "get":
        return _fail_check(f"{p0c_vec['id']}: exactly one get fault required")
    if int(faults[0].get("on_call", -1)) != 23:
        return _fail_check(
            f"{p0c_vec['id']}: get on_call must be 23 (17+5+1), got "
            f"{faults[0].get('on_call')}"
        )
    if faults[0].get("status") != "IO_ERROR":
        return _fail_check(f"{p0c_vec['id']}: fault status must be IO_ERROR")
    pt_p0c = p0c_vec["expected"]["port_trace"]
    if pt_p0c.count("begin:READ_ONLY") != 1:
        return _fail_check(f"{p0c_vec['id']}: single-txn begin pin fail")
    if pt_p0c.count("get") != 23:
        return _fail_check(
            f"{p0c_vec['id']}: port_trace get count must be 23, got "
            f"{pt_p0c.count('get')}"
        )
    # Last get is the Port failure; no further peer gets or CORRUPT note path.
    if pt_p0c[-3:] != ["get", "iter_close", "rollback"]:
        return _fail_check(
            f"{p0c_vec['id']}: port_trace must end get,iter_close,rollback"
        )
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode25_bind_exact_get_port_failure_note0(
                p0c_vec["candidate_binding"], p0c_vec["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{p0c_vec['id']}: model reject: {exc}")
    if p0c_vec["calls"] != exp_calls:
        return _fail_check(f"{p0c_vec['id']}: calls != independent model")
    if p0c_vec["expected"] != exp_expected:
        return _fail_check(f"{p0c_vec['id']}: expected != independent model")

    # ---- P0-D Mode22 INDEX/ABSENT + PVD + pair subject residual (#8/#15) ----
    p0d_kinds_got = {v["kind"] for v in p0d}
    if p0d_kinds_got != D3S2_P0D_KINDS:
        return _fail_check(f"p0d kinds inventory mismatch: {p0d_kinds_got}")
    p0d_by_kind = {v["kind"]: v for v in p0d}

    def _p0d_common_fail(vec: Dict[str, Any], *, peer_gets: int) -> Optional[str]:
        if vec.get("ownership") != OWNERSHIP_P0D:
            return f"{vec['id']}: ownership pin fail"
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return f"{vec['id']}: mutation_calls must be 0"
        if int(vec["expected"]["phase"]) != PHASE_FAILED:
            return f"{vec['id']}: phase must be FAILED"
        if vec["expected"]["final_status"] != "STORAGE_CORRUPT":
            return f"{vec['id']}: final_status must be STORAGE_CORRUPT"
        if int(vec["expected"]["has_sticky_primary"]) != 1:
            return f"{vec['id']}: sticky must be set"
        if vec["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
            return f"{vec['id']}: sticky_primary pin fail"
        if int(vec["expected"]["binding_complete_mask"]) != 0:
            return f"{vec['id']}: binding mask must stay 0"
        if int(vec["expected"]["adopted"]) != 0:
            return f"{vec['id']}: adopted must be 0"
        if int(vec["expected"]["d3_peer_get_count"]) != peer_gets:
            return (
                f"{vec['id']}: d3_peer_get_count must be {peer_gets}, got "
                f"{vec['expected']['d3_peer_get_count']}"
            )
        if (vec["expected"].get("port_trace") or []).count("begin:READ_ONLY") != 1:
            return f"{vec['id']}: single-txn begin pin fail"
        if vec["calls"][-1]["op"] != "abort":
            return f"{vec['id']}: fail path must end with abort"
        if any(c.get("op") == "begin_profiled_d3s1" for c in vec["calls"]):
            return f"{vec['id']}: dual-bound S1 begin forbidden"
        return None

    m22_idx = p0d_by_kind["mode22_att_unexpected_aii_index_present_corrupt"]
    err = _p0d_common_fail(m22_idx, peer_gets=5)
    if err:
        return _fail_check(err)
    if int(m22_idx["mode"]) != 22:
        return _fail_check(f"{m22_idx['id']}: mode must be 22")
    if int(m22_idx["expected"]["count_complete_mask"]) != MASK_ATTEMPT:
        return _fail_check(f"{m22_idx['id']}: count mask must be ATTEMPT only")
    if int(m22_idx["expected"]["count_complete_mask"]) & MASK_INDEX:
        return _fail_check(f"{m22_idx['id']}: INDEX count bit must stay 0")
    aii_rows = [r for r in m22_idx["rows"] if _domain_subtype(r) == 0x34]
    if len(aii_rows) != 1:
        return _fail_check(f"{m22_idx['id']}: exact 1 unexpected AII required")
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode22_att_unexpected_aii_index_present_corrupt(
                m22_idx["candidate_binding"], m22_idx["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_idx['id']}: model reject: {exc}")
    if m22_idx["calls"] != exp_calls:
        return _fail_check(f"{m22_idx['id']}: calls != independent model")
    if m22_idx["expected"] != exp_expected:
        return _fail_check(f"{m22_idx['id']}: expected != independent model")
    pt_idx = m22_idx["expected"]["port_trace"]
    if pt_idx[-4:] != ["get", "get", "get", "iter_close"] and not (
        pt_idx[-5:]
        == ["get", "get", "get", "iter_close", "rollback"]
    ):
        # allow rollback after close
        if pt_idx[-5:] != ["get", "get", "get", "iter_close", "rollback"]:
            return _fail_check(
                f"{m22_idx['id']}: must end carrier+primary+INDEX PRESENT "
                "gets then abort close"
            )

    m22_pri = p0d_by_kind["mode22_att_true_primary_delivery_absent_corrupt"]
    err = _p0d_common_fail(m22_pri, peer_gets=4)
    if err:
        return _fail_check(err)
    if int(m22_pri["mode"]) != 22:
        return _fail_check(f"{m22_pri['id']}: mode must be 22")
    if any(_domain_subtype(r) == 0x40 for r in m22_pri["rows"]):
        return _fail_check(f"{m22_pri['id']}: DELIVERY must be absent")
    if any(_domain_subtype(r) == 0x34 for r in m22_pri["rows"]):
        return _fail_check(f"{m22_pri['id']}: AII must be absent")
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode22_att_true_primary_delivery_absent_corrupt(
                m22_pri["candidate_binding"], m22_pri["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_pri['id']}: model reject: {exc}")
    if m22_pri["calls"] != exp_calls:
        return _fail_check(f"{m22_pri['id']}: calls != independent model")
    if m22_pri["expected"] != exp_expected:
        return _fail_check(f"{m22_pri['id']}: expected != independent model")

    m21_pvd = p0d_by_kind["mode21_att_primary_pvd_mismatch_corrupt"]
    err = _p0d_common_fail(m21_pvd, peer_gets=4)
    if err:
        return _fail_check(err)
    if int(m21_pvd["mode"]) != 21:
        return _fail_check(f"{m21_pvd['id']}: mode must be 21")
    if int(m21_pvd["expected"]["count_complete_mask"]) != (
        MASK_ATTEMPT | MASK_INDEX
    ):
        return _fail_check(f"{m21_pvd['id']}: count mask must be ATTEMPT|INDEX")
    # Independent: ATT PVD must not equal live ANCHOR VALUE_DIGEST.
    anc_rows = [r for r in m21_pvd["rows"] if _domain_subtype(r) == 0x20]
    att_rows = [r for r in m21_pvd["rows"] if _domain_subtype(r) == 0x31]
    if len(anc_rows) != 1 or len(att_rows) != 1:
        return _fail_check(f"{m21_pvd['id']}: need exact 1 ANCHOR and 1 ATT")
    anc_dig = _d3s1.value_digest(from_hex(anc_rows[0]["value_hex"]))
    att_pvd = _d3s1.extract_envelope(from_hex(att_rows[0]["value_hex"]))[2]
    if att_pvd == anc_dig:
        return _fail_check(
            f"{m21_pvd['id']}: ATT PVD must differ from live ANCHOR digest"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode21_att_primary_pvd_mismatch_corrupt(
            m21_pvd["candidate_binding"], m21_pvd["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_pvd['id']}: model reject: {exc}")
    if m21_pvd["calls"] != exp_calls:
        return _fail_check(f"{m21_pvd['id']}: calls != independent model")
    if m21_pvd["expected"] != exp_expected:
        return _fail_check(f"{m21_pvd['id']}: expected != independent model")

    m21_raw = p0d_by_kind["mode21_att_index_pair_subject_raw_mismatch_corrupt"]
    err = _p0d_common_fail(m21_raw, peer_gets=5)
    if err:
        return _fail_check(err)
    if int(m21_raw["mode"]) != 21:
        return _fail_check(f"{m21_raw['id']}: mode must be 21")
    if int(m21_raw["expected"]["count_complete_mask"]) != (
        MASK_ATTEMPT | MASK_INDEX
    ):
        return _fail_check(f"{m21_raw['id']}: count mask must be ATTEMPT|INDEX")
    aii_raw_rows = [r for r in m21_raw["rows"] if _domain_subtype(r) == 0x34]
    att_raw_rows = [r for r in m21_raw["rows"] if _domain_subtype(r) == 0x31]
    cp_raw_rows = [r for r in m21_raw["rows"] if _domain_subtype(r) == 0x63]
    if len(aii_raw_rows) != 1 or len(att_raw_rows) != 1 or len(cp_raw_rows) != 1:
        return _fail_check(
            f"{m21_raw['id']}: need exact 1 AII + 1 ATT + 1 CLEANUP_PLAN"
        )
    try:
        _aid_a, aii_txn, _k, _rkd, _p = _parse_attempt_id_index(
            from_hex(aii_raw_rows[0]["value_hex"])
        )
        _ok, _or, att_id, att_txn, _ak, _pk, _ap = _parse_attempt_tx(
            from_hex(att_raw_rows[0]["value_hex"])
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_raw['id']}: parse fail: {exc}")
    if aii_txn == att_txn:
        return _fail_check(
            f"{m21_raw['id']}: AII txn must mismatch ATT for subject/raw fail"
        )
    if _aid_a != att_id:
        return _fail_check(
            f"{m21_raw['id']}: AII attempt_id must match ATT (pair key PRESENT)"
        )
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode21_att_index_pair_subject_raw_mismatch_corrupt(
                m21_raw["candidate_binding"], m21_raw["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_raw['id']}: model reject: {exc}")
    if m21_raw["calls"] != exp_calls:
        return _fail_check(f"{m21_raw['id']}: calls != independent model")
    if m21_raw["expected"] != exp_expected:
        return _fail_check(f"{m21_raw['id']}: expected != independent model")

    # ---- P1-A ordinary stream count under/over + empty-secondary (#4/#14) ----
    p1a_kinds_got = {v["kind"] for v in p1a}
    if p1a_kinds_got != D3S2_P1A_KINDS:
        return _fail_check(f"p1a kinds inventory mismatch: {p1a_kinds_got}")
    p1a_by_kind = {v["kind"]: v for v in p1a}

    def _p1a_common_fail(
        vec: Dict[str, Any],
        *,
        peer_gets: int,
        count_mask: int,
        mode: int,
    ) -> Optional[str]:
        if int(vec["mode"]) != mode:
            return f"{vec['id']}: mode must be {mode}"
        if vec.get("ownership") != OWNERSHIP_P1A:
            return f"{vec['id']}: ownership pin fail"
        if vec.get("faults"):
            return f"{vec['id']}: faults must be empty (semantic corrupt)"
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return f"{vec['id']}: mutation_calls must be 0"
        if int(vec["expected"]["phase"]) != PHASE_FAILED:
            return f"{vec['id']}: phase must be FAILED"
        if vec["expected"]["final_status"] != "STORAGE_CORRUPT":
            return f"{vec['id']}: final_status must be STORAGE_CORRUPT"
        if int(vec["expected"]["has_sticky_primary"]) != 1:
            return f"{vec['id']}: sticky must be set"
        if vec["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
            return f"{vec['id']}: sticky_primary pin fail"
        if int(vec["expected"]["binding_complete_mask"]) != 0:
            return f"{vec['id']}: binding mask must stay 0"
        if int(vec["expected"]["count_complete_mask"]) != count_mask:
            return (
                f"{vec['id']}: count_complete_mask must be {count_mask}, got "
                f"{vec['expected']['count_complete_mask']}"
            )
        if int(vec["expected"]["adopted"]) != 0:
            return f"{vec['id']}: adopted must be 0"
        if int(vec["expected"]["d3_peer_get_count"]) != peer_gets:
            return (
                f"{vec['id']}: d3_peer_get_count must be {peer_gets}, got "
                f"{vec['expected']['d3_peer_get_count']}"
            )
        if (vec["expected"].get("port_trace") or []).count("begin:READ_ONLY") != 1:
            return f"{vec['id']}: single-txn begin pin fail"
        if vec["calls"][-1]["op"] != "abort":
            return f"{vec['id']}: fail path must end with abort"
        if any(c.get("op") == "begin_profiled_d3s1" for c in vec["calls"]):
            return f"{vec['id']}: dual-bound S1 begin forbidden"
        # CLEANUP_PLAN must be ABSENT on ordinary count path.
        for r in vec["rows"]:
            k = from_hex(r["key_hex"])
            if len(k) >= 10 and k[8] == 6 and k[9] == 0x63:
                return f"{vec['id']}: CLEANUP_PLAN forbidden on ordinary count path"
        return None

    p1a_specs = [
        (
            "mode21_app_attempt_stream_overcount_corrupt",
            run_d3s2_mode21_app_attempt_stream_overcount_corrupt,
            2,
            0,
            21,
        ),
        (
            "mode21_cancel_attempt_stream_overcount_corrupt",
            run_d3s2_mode21_cancel_attempt_stream_overcount_corrupt,
            2,
            0,
            21,
        ),
        (
            "mode21_index_stream_undercount_corrupt",
            run_d3s2_mode21_index_stream_undercount_corrupt,
            2,
            MASK_ATTEMPT,
            21,
        ),
        (
            "mode22_app_first_empty_secondary_undercount_corrupt",
            run_d3s2_mode22_app_first_empty_secondary_undercount_corrupt,
            2,
            0,
            22,
        ),
        (
            "mode22_cancel_first_cancel_undercount_corrupt",
            run_d3s2_mode22_cancel_first_cancel_undercount_corrupt,
            2,
            0,
            22,
        ),
        (
            "mode26_mgmt_stream_overcount_corrupt",
            run_d3s2_mode26_mgmt_stream_overcount_corrupt,
            0,
            0,
            26,
        ),
    ]
    for kind, model_fn, peer, cmask, mode in p1a_specs:
        vec = p1a_by_kind[kind]
        err = _p1a_common_fail(vec, peer_gets=peer, count_mask=cmask, mode=mode)
        if err:
            return _fail_check(err)
        try:
            exp_calls, exp_expected = model_fn(vec["candidate_binding"], vec["rows"])
        except SystemExit as exc:
            return _fail_check(f"{vec['id']}: model reject: {exc}")
        if vec["calls"] != exp_calls:
            return _fail_check(f"{vec['id']}: calls != independent model")
        if vec["expected"] != exp_expected:
            return _fail_check(f"{vec['id']}: expected != independent model")

    # ---- P1-D profile mismatch / future_profile evaluator-off (#12) ----
    p1d_kinds_got = {v["kind"] for v in p1d}
    if p1d_kinds_got != D3S2_P1D_KINDS:
        return _fail_check(f"p1d kinds inventory mismatch: {p1d_kinds_got}")
    p1d_by_kind = {v["kind"]: v for v in p1d}

    def _p1d_common(vec: Dict[str, Any], *, mismatch: int, future: int) -> Optional[str]:
        if int(vec["mode"]) != 21:
            return f"{vec['id']}: mode must be 21"
        if vec.get("ownership") != OWNERSHIP_P1D:
            return f"{vec['id']}: ownership pin fail"
        if vec.get("faults"):
            return f"{vec['id']}: faults must be empty"
        exp = vec["expected"]
        if exp.get("final_status") != "UNSUPPORTED":
            return f"{vec['id']}: final_status must be UNSUPPORTED"
        if int(exp.get("adopted", -1)) != 0:
            return f"{vec['id']}: adopted must be 0"
        if int(exp.get("phase", -1)) != PHASE_BASELINE:
            return f"{vec['id']}: phase must stay BASELINE (not COMPLETE)"
        if int(exp.get("flags", -1)) != FLAG_BASELINE_DONE:
            return f"{vec['id']}: flags must be BASELINE_DONE only"
        if int(exp.get("flags", 0)) & FLAG_COMPLETE_READY:
            return f"{vec['id']}: COMPLETE_READY forbidden (false authority)"
        if int(exp.get("count_complete_mask", -1)) != 0:
            return f"{vec['id']}: count mask must be 0"
        if int(exp.get("binding_complete_mask", -1)) != 0:
            return f"{vec['id']}: binding mask must be 0"
        if int(exp.get("profile_exact_active", -1)) != 0:
            return f"{vec['id']}: profile_exact_active must be 0"
        if int(exp.get("profile_mismatch", -1)) != mismatch:
            return f"{vec['id']}: profile_mismatch pin fail"
        if int(exp.get("future_profile_candidate", -1)) != future:
            return f"{vec['id']}: future_profile_candidate pin fail"
        if int(exp.get("recognizable_future_seen", -1)) != 0:
            return f"{vec['id']}: recognizable_future_seen must be 0"
        if int(exp.get("iter_open_count", -1)) != 1:
            return f"{vec['id']}: iter_open_count must be 1 (no INTERNAL reopen)"
        if int(exp.get("d3_peer_get_count", -1)) != 0:
            return f"{vec['id']}: peer_get must be 0"
        if int(exp.get("mutation_calls", -1)) != 0:
            return f"{vec['id']}: mutation_calls must be 0"
        if int(exp.get("has_sticky_primary", -1)) != 0:
            return f"{vec['id']}: sticky must be 0"
        if int(exp.get("family14_row_count", -1)) != 17:
            return f"{vec['id']}: family14_row_count must be 17"
        if int(exp.get("current_domain_key_count", -1)) != 0:
            return f"{vec['id']}: current_domain_key_count must be 0"
        pt = exp.get("port_trace") or []
        if pt.count("begin:READ_ONLY") != 1:
            return f"{vec['id']}: single-txn begin pin fail"
        if pt.count("iter_open:prefix0") != 1:
            return f"{vec['id']}: single baseline iter_open only"
        if pt.count("get") != 17:
            return f"{vec['id']}: exact 17 profile gets"
        # No peer gets after first iter_open.
        first_open = pt.index("iter_open:prefix0")
        if any(t == "get" for t in pt[first_open + 1 :]):
            return f"{vec['id']}: INTERNAL/BIND get after iter_open forbidden"
        ops = [c.get("op") for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2" or ops[-1] != "finalize":
            return f"{vec['id']}: calls must begin_profiled_d3s2 … finalize"
        if ops.count("d3s2_drive") != 1:
            return f"{vec['id']}: exactly one baseline d3s2_drive"
        if any(c.get("op") == "begin_profiled_d3s1" for c in vec["calls"]):
            return f"{vec['id']}: dual-bound S1 begin forbidden"
        if int(exp.get("ok_row_count", -1)) < 18:
            return f"{vec['id']}: domain rows required (ok_row_count>=18)"
        return None

    m21_mm = p1d_by_kind["mode21_profile_mismatch_evaluator_off_unsupported"]
    err = _p1d_common(m21_mm, mismatch=1, future=0)
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = run_d3s2_profile_evaluator_off(
            m21_mm["candidate_binding"],
            m21_mm["rows"],
            profile_mismatch=1,
            future_profile_candidate=0,
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_mm['id']}: model reject: {exc}")
    if m21_mm["calls"] != exp_calls:
        return _fail_check(f"{m21_mm['id']}: calls != independent model")
    if m21_mm["expected"] != exp_expected:
        return _fail_check(f"{m21_mm['id']}: expected != independent model")

    m21_fp = p1d_by_kind["mode21_future_profile_evaluator_off_unsupported"]
    err = _p1d_common(m21_fp, mismatch=0, future=1)
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = run_d3s2_profile_evaluator_off(
            m21_fp["candidate_binding"],
            m21_fp["rows"],
            profile_mismatch=0,
            future_profile_candidate=1,
        )
    except SystemExit as exc:
        return _fail_check(f"{m21_fp['id']}: model reject: {exc}")
    if m21_fp["calls"] != exp_calls:
        return _fail_check(f"{m21_fp['id']}: calls != independent model")
    if m21_fp["expected"] != exp_expected:
        return _fail_check(f"{m21_fp['id']}: expected != independent model")
    # Fail-closed: mismatch and future stored profiles must not be identical.
    if m21_mm["rows"][0]["value_hex"] == m21_fp["rows"][0]["value_hex"]:
        return _fail_check("p1d mismatch/future stored binding must differ")

    # ---- P1-D2 count-green without BIND false-terminal (#10) ----
    p1d2_kinds_got = {v["kind"] for v in p1d2}
    if p1d2_kinds_got != D3S2_P1D2_KINDS:
        return _fail_check(f"p1d2 kinds inventory mismatch: {p1d2_kinds_got}")
    p1d2_vec = p1d2[0]
    if p1d2_vec["kind"] != "mode21_count_green_bind_incomplete_false_terminal_ok":
        return _fail_check("p1d2[0] kind pin fail")
    if int(p1d2_vec["mode"]) != 21:
        return _fail_check(f"{p1d2_vec['id']}: mode must be 21")
    if p1d2_vec.get("ownership") != OWNERSHIP_P1D2:
        return _fail_check(f"{p1d2_vec['id']}: ownership pin fail")
    if p1d2_vec.get("faults"):
        return _fail_check(f"{p1d2_vec['id']}: faults must be empty")
    exp_p1d2 = p1d2_vec["expected"]
    if exp_p1d2.get("final_status") != "OK":
        return _fail_check(f"{p1d2_vec['id']}: final_status must be OK (resume COMPLETE)")
    if int(exp_p1d2.get("adopted", -1)) != 1:
        return _fail_check(f"{p1d2_vec['id']}: adopted must be 1 after resume")
    if int(exp_p1d2.get("phase", -1)) != PHASE_COMPLETE:
        return _fail_check(f"{p1d2_vec['id']}: terminal phase must be COMPLETE")
    if int(exp_p1d2.get("count_complete_mask", -1)) != (MASK_ATTEMPT | MASK_INDEX):
        return _fail_check(f"{p1d2_vec['id']}: terminal count mask pin fail")
    if int(exp_p1d2.get("binding_complete_mask", -1)) != (MASK_ATTEMPT | MASK_INDEX):
        return _fail_check(f"{p1d2_vec['id']}: terminal binding mask pin fail")
    if (int(exp_p1d2.get("flags", 0)) & FLAG_COMPLETE_READY) == 0:
        return _fail_check(f"{p1d2_vec['id']}: terminal COMPLETE_READY required")
    if int(exp_p1d2.get("has_sticky_primary", -1)) != 0:
        return _fail_check(f"{p1d2_vec['id']}: sticky must be 0")
    if int(exp_p1d2.get("mutation_calls", -1)) != 0:
        return _fail_check(f"{p1d2_vec['id']}: mutation_calls must be 0")
    if int(exp_p1d2.get("d3_peer_get_count", -1)) != 7:
        return _fail_check(f"{p1d2_vec['id']}: d3_peer_get_count must be 7")
    if int(exp_p1d2.get("iter_open_count", -1)) != 7:
        return _fail_check(f"{p1d2_vec['id']}: iter_open_count must be 7")
    pt_p1d2 = exp_p1d2.get("port_trace") or []
    if pt_p1d2.count("begin:READ_ONLY") != 1:
        return _fail_check(f"{p1d2_vec['id']}: single-txn begin pin fail")
    # Exactly one checkpoint + probe; no COMPLETE_READY at checkpoint.
    cp_p1d2 = [
        c
        for c in p1d2_vec["calls"]
        if int(c.get("has_checkpoint", 0)) == 1
    ]
    if len(cp_p1d2) != 1:
        return _fail_check(f"{p1d2_vec['id']}: exactly one checkpoint required")
    cp = cp_p1d2[0]
    if int(cp["cp_phase"]) != PHASE_BIND_ATTEMPT:
        return _fail_check(f"{p1d2_vec['id']}: cp_phase must be BIND_ATTEMPT")
    if int(cp["cp_count_complete_mask"]) != (MASK_ATTEMPT | MASK_INDEX):
        return _fail_check(f"{p1d2_vec['id']}: cp count mask must be green")
    if int(cp["cp_binding_complete_mask"]) != 0:
        return _fail_check(f"{p1d2_vec['id']}: cp binding mask must be 0")
    if (int(cp["cp_flags"]) & FLAG_COMPLETE_READY) != 0:
        return _fail_check(f"{p1d2_vec['id']}: COMPLETE_READY forbidden at probe")
    if (int(cp["cp_flags"]) & FLAG_BIND_PHASE_ACTIVE) == 0:
        return _fail_check(f"{p1d2_vec['id']}: BIND_PHASE_ACTIVE required at probe")
    if int(cp["cp_focus_live"]) != 0:
        return _fail_check(f"{p1d2_vec['id']}: focus_live must be 0 at BIND entry")
    if int(cp["cp_begin_calls"]) != 1:
        return _fail_check(f"{p1d2_vec['id']}: begin_calls must be 1")
    if int(cp["cp_iter_open_calls"]) != 6:
        return _fail_check(f"{p1d2_vec['id']}: iter_open_calls at BIND entry must be 6")
    if int(cp["cp_iter_close_calls"]) != 5:
        return _fail_check(f"{p1d2_vec['id']}: iter_close_calls at BIND entry must be 5")
    if int(cp["cp_trace_count"]) != 141:
        return _fail_check(f"{p1d2_vec['id']}: cp_trace_count must be 141")
    if int(cp["cp_last_carrier_key_len"]) <= 0:
        return _fail_check(f"{p1d2_vec['id']}: last_carrier_key_len must be > 0")
    probe_calls = [
        c
        for c in p1d2_vec["calls"]
        if c.get("op") == "probe_false_terminal_finalize"
    ]
    if len(probe_calls) != 1:
        return _fail_check(
            f"{p1d2_vec['id']}: exactly one probe_false_terminal_finalize"
        )
    if probe_calls[0].get("expected_status") != "INVALID_STATE":
        return _fail_check(
            f"{p1d2_vec['id']}: probe expected_status must be INVALID_STATE"
        )
    ops_p1d2 = [c.get("op") for c in p1d2_vec["calls"]]
    if ops_p1d2[0] != "begin_profiled_d3s2" or ops_p1d2[-1] != "finalize":
        return _fail_check(f"{p1d2_vec['id']}: calls must begin … finalize")
    if ops_p1d2.count("d3s2_drive") != 7:
        return _fail_check(f"{p1d2_vec['id']}: exactly 7 d3s2_drive")
    if any(c.get("op") == "begin_profiled_d3s1" for c in p1d2_vec["calls"]):
        return _fail_check(f"{p1d2_vec['id']}: dual-bound S1 begin forbidden")
    # Probe must follow checkpoint immediately; READY must not appear mid-path.
    cp_i = next(
        i
        for i, c in enumerate(p1d2_vec["calls"])
        if int(c.get("has_checkpoint", 0)) == 1
    )
    if ops_p1d2[cp_i + 1] != "probe_false_terminal_finalize":
        return _fail_check(
            f"{p1d2_vec['id']}: probe must immediately follow checkpoint"
        )
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode21_count_green_bind_incomplete_false_terminal(
                p1d2_vec["candidate_binding"], p1d2_vec["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{p1d2_vec['id']}: model reject: {exc}")
    if p1d2_vec["calls"] != exp_calls:
        return _fail_check(f"{p1d2_vec['id']}: calls != independent model")
    if p1d2_vec["expected"] != exp_expected:
        return _fail_check(f"{p1d2_vec['id']}: expected != independent model")
    # Port-trace must match ordinary Mode21 success (probe is Port 0).
    try:
        _sc, success_exp = run_d3s2_mode21_state_cum1_att_aii_success(
            p1d2_vec["candidate_binding"], p1d2_vec["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{p1d2_vec['id']}: success-model reject: {exc}")
    if pt_p1d2 != success_exp.get("port_trace"):
        return _fail_check(
            f"{p1d2_vec['id']}: port_trace must equal Mode21 success "
            f"(probe Port 0; no extra/missing Port ops)"
        )

    # ---- P1-B1 CLEANUP_PLAN Modes22–23 (#5 / §18.13.8) ----
    p1b1_kinds_got = {v["kind"] for v in p1b1}
    if p1b1_kinds_got != D3S2_P1B1_KINDS:
        return _fail_check(f"p1b1 kinds inventory mismatch: {p1b1_kinds_got}")
    p1b1_by_kind = {v["kind"]: v for v in p1b1}

    m22_skip = p1b1_by_kind["mode22_cleanup_plan_present_ordinary_skip_ok"]
    if int(m22_skip["mode"]) != 22:
        return _fail_check(f"{m22_skip['id']}: mode must be 22")
    if m22_skip.get("ownership") != OWNERSHIP_P1B1:
        return _fail_check(f"{m22_skip['id']}: ownership pin fail")
    if m22_skip.get("faults"):
        return _fail_check(f"{m22_skip['id']}: faults must be empty")
    exp_m22 = m22_skip["expected"]
    if exp_m22.get("final_status") != "OK":
        return _fail_check(f"{m22_skip['id']}: final_status must be OK")
    if int(exp_m22.get("adopted", -1)) != 1:
        return _fail_check(f"{m22_skip['id']}: adopted must be 1")
    if int(exp_m22.get("phase", -1)) != PHASE_COMPLETE:
        return _fail_check(f"{m22_skip['id']}: terminal phase must be COMPLETE")
    if int(exp_m22.get("has_sticky_primary", -1)) != 0:
        return _fail_check(f"{m22_skip['id']}: sticky must be 0")
    if int(exp_m22.get("mutation_calls", -1)) != 0:
        return _fail_check(f"{m22_skip['id']}: mutation_calls must be 0")
    if int(exp_m22.get("d3_peer_get_count", -1)) != 2:
        return _fail_check(f"{m22_skip['id']}: d3_peer_get_count must be 2")
    if int(exp_m22.get("count_complete_mask", -1)) != MASK_ATTEMPT:
        return _fail_check(f"{m22_skip['id']}: count_complete_mask must be ATTEMPT")
    if int(exp_m22.get("binding_complete_mask", -1)) != MASK_ATTEMPT:
        return _fail_check(f"{m22_skip['id']}: binding_complete_mask must be ATTEMPT")
    pt_m22 = exp_m22.get("port_trace") or []
    if pt_m22.count("begin:READ_ONLY") != 1:
        return _fail_check(f"{m22_skip['id']}: single-txn begin pin fail")
    if pt_m22.count("get") != 19:
        return _fail_check(
            f"{m22_skip['id']}: 17 profile + 2 setup gets (CANCEL+CLEANUP) required"
        )
    # Matching CLEANUP_PLAN row present; no ATTEMPT.
    m22_att = sum(
        1
        for r in m22_skip["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x31
    )
    m22_cp = sum(
        1
        for r in m22_skip["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if m22_att != 0:
        return _fail_check(f"{m22_skip['id']}: ATTEMPT band must be empty")
    if m22_cp != 1:
        return _fail_check(f"{m22_skip['id']}: exact 1 CLEANUP_PLAN required")
    # Checkpoint: cleanup_skip=1 at natural FOCUS open after SELECT setup.
    cp_m22 = [
        c for c in m22_skip["calls"] if int(c.get("has_checkpoint", 0)) == 1
    ]
    if len(cp_m22) != 1:
        return _fail_check(f"{m22_skip['id']}: exactly one checkpoint required")
    if int(cp_m22[0]["cp_cleanup_skip"]) != 1:
        return _fail_check(f"{m22_skip['id']}: cp_cleanup_skip must be 1")
    if int(cp_m22[0]["cp_phase"]) != PHASE_FOCUS_ATTEMPT:
        return _fail_check(f"{m22_skip['id']}: cp_phase must be FOCUS_ATTEMPT")
    if int(cp_m22[0]["cp_focus_live"]) != 1:
        return _fail_check(f"{m22_skip['id']}: cp_focus_live must be 1")
    if int(cp_m22[0]["cp_begin_calls"]) != 1:
        return _fail_check(f"{m22_skip['id']}: begin_calls must be 1")
    if (int(cp_m22[0]["cp_flags"]) & FLAG_COMPLETE_READY) != 0:
        return _fail_check(f"{m22_skip['id']}: COMPLETE_READY forbidden at checkpoint")
    # Matching subject: CP key rebuild from DELIVERY KEY_DIGEST.
    dlv_rows = [
        r
        for r in m22_skip["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x40
    ]
    cp_rows = [
        r
        for r in m22_skip["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    ]
    if len(dlv_rows) != 1 or len(cp_rows) != 1:
        return _fail_check(f"{m22_skip['id']}: DLV/CP row inventory fail")
    dlv_kd = _d3s1.key_digest(from_hex(dlv_rows[0]["key_hex"]))
    if _rebuild_cleanup_plan_key(3, dlv_kd) != from_hex(cp_rows[0]["key_hex"]):
        return _fail_check(
            f"{m22_skip['id']}: CLEANUP_PLAN key must match DELIVERY subject"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode22_cleanup_plan_ordinary_skip_success(
            m22_skip["candidate_binding"], m22_skip["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_skip['id']}: model reject: {exc}")
    if m22_skip["calls"] != exp_calls:
        return _fail_check(f"{m22_skip['id']}: calls != independent model")
    if m22_skip["expected"] != exp_expected:
        return _fail_check(f"{m22_skip['id']}: expected != independent model")

    m23_ord = p1b1_by_kind["mode23_cleanup_plan_present_still_ordinary_corrupt"]
    if int(m23_ord["mode"]) != 23:
        return _fail_check(f"{m23_ord['id']}: mode must be 23")
    if m23_ord.get("ownership") != OWNERSHIP_P1B1:
        return _fail_check(f"{m23_ord['id']}: ownership pin fail")
    if m23_ord.get("faults"):
        return _fail_check(f"{m23_ord['id']}: faults must be empty")
    exp_m23 = m23_ord["expected"]
    if exp_m23.get("final_status") != "STORAGE_CORRUPT":
        return _fail_check(f"{m23_ord['id']}: final_status must be STORAGE_CORRUPT")
    if int(exp_m23.get("adopted", -1)) != 0:
        return _fail_check(f"{m23_ord['id']}: adopted must be 0")
    if int(exp_m23.get("phase", -1)) != PHASE_FAILED:
        return _fail_check(f"{m23_ord['id']}: terminal phase must be FAILED")
    if int(exp_m23.get("has_sticky_primary", -1)) != 1:
        return _fail_check(f"{m23_ord['id']}: sticky must be 1")
    if exp_m23.get("sticky_primary") != "STORAGE_CORRUPT":
        return _fail_check(f"{m23_ord['id']}: sticky_primary pin fail")
    if int(exp_m23.get("mutation_calls", -1)) != 0:
        return _fail_check(f"{m23_ord['id']}: mutation_calls must be 0")
    if int(exp_m23.get("d3_peer_get_count", -1)) != (MODE23_ACCEPTED_L + 1):
        return _fail_check(
            f"{m23_ord['id']}: d3_peer_get_count must be L+1 known-slot gets"
        )
    pt_m23 = exp_m23.get("port_trace") or []
    if pt_m23.count("begin:READ_ONLY") != 1:
        return _fail_check(f"{m23_ord['id']}: single-txn begin pin fail")
    if pt_m23.count("get") != 17 + (MODE23_ACCEPTED_L + 1):
        return _fail_check(
            f"{m23_ord['id']}: 17 profile + L+1 known-slot gets "
            f"(no CLEANUP setup get)"
        )
    # Matching TX CLEANUP_PLAN present; zero EVIDENCE.
    m23_ev = sum(
        1
        for r in m23_ord["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x32
    )
    m23_cp = sum(
        1
        for r in m23_ord["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    m23_st = sum(
        1
        for r in m23_ord["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    )
    if m23_ev != 0:
        return _fail_check(f"{m23_ord['id']}: EVIDENCE band must be empty")
    if m23_cp != 1:
        return _fail_check(f"{m23_ord['id']}: exact 1 CLEANUP_PLAN required")
    if m23_st != 1:
        return _fail_check(f"{m23_ord['id']}: exact 1 STATE carrier required")
    cp_m23 = [
        c for c in m23_ord["calls"] if int(c.get("has_checkpoint", 0)) == 1
    ]
    if len(cp_m23) != 1:
        return _fail_check(f"{m23_ord['id']}: exactly one checkpoint required")
    if int(cp_m23[0]["cp_cleanup_skip"]) != 0:
        return _fail_check(f"{m23_ord['id']}: cp_cleanup_skip must be 0")
    if int(cp_m23[0]["cp_phase"]) != PHASE_FAILED:
        return _fail_check(f"{m23_ord['id']}: cp_phase must be FAILED")
    if int(cp_m23[0]["cp_focus_live"]) != 1:
        return _fail_check(f"{m23_ord['id']}: cp_focus_live must be 1")
    if int(cp_m23[0]["cp_begin_calls"]) != 1:
        return _fail_check(f"{m23_ord['id']}: begin_calls must be 1")
    # Matching subject: CP key rebuild from ANCHOR KEY_DIGEST.
    anc_rows = [
        r
        for r in m23_ord["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x20
    ]
    cp_rows_m23 = [
        r
        for r in m23_ord["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    ]
    if len(anc_rows) != 1 or len(cp_rows_m23) != 1:
        return _fail_check(f"{m23_ord['id']}: ANCHOR/CP row inventory fail")
    anc_kd = _d3s1.key_digest(from_hex(anc_rows[0]["key_hex"]))
    if _rebuild_cleanup_plan_key(2, anc_kd) != from_hex(cp_rows_m23[0]["key_hex"]):
        return _fail_check(
            f"{m23_ord['id']}: CLEANUP_PLAN key must match ANCHOR subject"
        )
    # Typed CP body subject_kind must be TX=2.
    sk_m23, _ph, _raw, subj_pkd_m23, _spvd = _parse_cleanup_plan_subject(
        from_hex(cp_rows_m23[0]["value_hex"])
    )
    if sk_m23 != 2 or subj_pkd_m23 != anc_kd:
        return _fail_check(
            f"{m23_ord['id']}: CLEANUP_PLAN body subject must match TX ANCHOR"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode23_cleanup_plan_still_ordinary_corrupt(
            m23_ord["candidate_binding"], m23_ord["rows"], MODE23_ACCEPTED_L
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_ord['id']}: model reject: {exc}")
    if m23_ord["calls"] != exp_calls:
        return _fail_check(f"{m23_ord['id']}: calls != independent model")
    if m23_ord["expected"] != exp_expected:
        return _fail_check(f"{m23_ord['id']}: expected != independent model")

    # ---- P1-B2 CLEANUP_PLAN Modes24–26 still-ordinary (#5 residual) ----
    p1b2_kinds_got = {v["kind"] for v in p1b2}
    if p1b2_kinds_got != D3S2_P1B2_KINDS:
        return _fail_check(f"p1b2 kinds inventory mismatch: {p1b2_kinds_got}")
    p1b2_by_kind = {v["kind"]: v for v in p1b2}

    def _p1b2_still_ordinary_common(
        vec: Dict[str, Any],
        *,
        mode: int,
        peer_gets: int,
        subject_kind: int,
        primary_subtype: int,
        forbid_subtype: int,
        model_fn,
        model_args: Tuple[Any, ...] = (),
    ) -> Optional[str]:
        if int(vec["mode"]) != mode:
            return f"{vec['id']}: mode must be {mode}"
        if vec.get("ownership") != OWNERSHIP_P1B2:
            return f"{vec['id']}: ownership pin fail"
        if vec.get("faults"):
            return f"{vec['id']}: faults must be empty"
        exp = vec["expected"]
        if exp.get("final_status") != "STORAGE_CORRUPT":
            return f"{vec['id']}: final_status must be STORAGE_CORRUPT"
        if int(exp.get("adopted", -1)) != 0:
            return f"{vec['id']}: adopted must be 0"
        if int(exp.get("phase", -1)) != PHASE_FAILED:
            return f"{vec['id']}: terminal phase must be FAILED"
        if int(exp.get("has_sticky_primary", -1)) != 1:
            return f"{vec['id']}: sticky must be 1"
        if exp.get("sticky_primary") != "STORAGE_CORRUPT":
            return f"{vec['id']}: sticky_primary pin fail"
        if int(exp.get("mutation_calls", -1)) != 0:
            return f"{vec['id']}: mutation_calls must be 0"
        if int(exp.get("d3_peer_get_count", -1)) != peer_gets:
            return f"{vec['id']}: d3_peer_get_count must be {peer_gets}"
        pt = exp.get("port_trace") or []
        if pt.count("begin:READ_ONLY") != 1:
            return f"{vec['id']}: single-txn begin pin fail"
        # No CLEANUP setup get for Modes24–26: profile 17 + peer_gets only.
        if pt.count("get") != 17 + peer_gets:
            return (
                f"{vec['id']}: 17 profile + {peer_gets} peer gets "
                f"(no CLEANUP setup get), got {pt.count('get')}"
            )
        forbid_n = sum(
            1
            for r in vec["rows"]
            if len(from_hex(r["key_hex"])) >= 10
            and from_hex(r["key_hex"])[8] == 6
            and from_hex(r["key_hex"])[9] == forbid_subtype
        )
        if forbid_n != 0:
            return f"{vec['id']}: forbidden secondary subtype must be empty"
        cp_n = sum(
            1
            for r in vec["rows"]
            if len(from_hex(r["key_hex"])) >= 10
            and from_hex(r["key_hex"])[8] == 6
            and from_hex(r["key_hex"])[9] == 0x63
        )
        if cp_n != 1:
            return f"{vec['id']}: exact 1 CLEANUP_PLAN required"
        cps = [
            c for c in vec["calls"] if int(c.get("has_checkpoint", 0)) == 1
        ]
        if len(cps) != 1:
            return f"{vec['id']}: exactly one checkpoint required"
        if int(cps[0]["cp_cleanup_skip"]) != 0:
            return f"{vec['id']}: cp_cleanup_skip must be 0"
        if int(cps[0]["cp_phase"]) != PHASE_FAILED:
            return f"{vec['id']}: cp_phase must be FAILED"
        if int(cps[0]["cp_focus_live"]) != 1:
            return f"{vec['id']}: cp_focus_live must be 1"
        if int(cps[0]["cp_begin_calls"]) != 1:
            return f"{vec['id']}: begin_calls must be 1"
        primary_rows = [
            r
            for r in vec["rows"]
            if len(from_hex(r["key_hex"])) >= 10
            and from_hex(r["key_hex"])[8] == 6
            and from_hex(r["key_hex"])[9] == primary_subtype
        ]
        cp_rows = [
            r
            for r in vec["rows"]
            if len(from_hex(r["key_hex"])) >= 10
            and from_hex(r["key_hex"])[8] == 6
            and from_hex(r["key_hex"])[9] == 0x63
        ]
        if len(primary_rows) != 1 or len(cp_rows) != 1:
            return f"{vec['id']}: primary/CP row inventory fail"
        pkd = _d3s1.key_digest(from_hex(primary_rows[0]["key_hex"]))
        if _rebuild_cleanup_plan_key(subject_kind, pkd) != from_hex(
            cp_rows[0]["key_hex"]
        ):
            return f"{vec['id']}: CLEANUP_PLAN key must match primary subject"
        sk, _ph, _raw, subj_pkd, _spvd = _parse_cleanup_plan_subject(
            from_hex(cp_rows[0]["value_hex"])
        )
        if sk != subject_kind or subj_pkd != pkd:
            return f"{vec['id']}: CLEANUP_PLAN body subject must match primary"
        try:
            exp_calls, exp_expected = model_fn(
                vec["candidate_binding"], vec["rows"], *model_args
            )
        except SystemExit as exc:
            return f"{vec['id']}: model reject: {exc}"
        if vec["calls"] != exp_calls:
            return f"{vec['id']}: calls != independent model"
        if vec["expected"] != exp_expected:
            return f"{vec['id']}: expected != independent model"
        return None

    m24_ord = p1b2_by_kind["mode24_cleanup_plan_present_still_ordinary_corrupt"]
    err = _p1b2_still_ordinary_common(
        m24_ord,
        mode=24,
        peer_gets=4,
        subject_kind=3,
        primary_subtype=0x40,  # DELIVERY
        forbid_subtype=0x42,  # REVERSE_REPLY
        model_fn=run_d3s2_mode24_cleanup_plan_still_ordinary_corrupt,
    )
    if err:
        return _fail_check(err)

    m25_ord = p1b2_by_kind["mode25_cleanup_plan_present_still_ordinary_corrupt"]
    err = _p1b2_still_ordinary_common(
        m25_ord,
        mode=25,
        peer_gets=5,
        subject_kind=2,
        primary_subtype=0x20,  # ANCHOR
        forbid_subtype=0xFF,  # no generic forbid; RECENT checked below
        model_fn=run_d3s2_mode25_cleanup_plan_still_ordinary_corrupt,
    )
    if err:
        return _fail_check(err)
    # Mode25: forbid RECENT (kind=2) specifically among RETRY rows.
    for r in m25_ord["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x51:
            _st, body, _ = _d3s1.extract_envelope(from_hex(r["value_hex"]))
            if struct.unpack_from(">H", body, 16)[0] == RS_KIND_RECENT:
                return _fail_check(f"{m25_ord['id']}: RECENT must be absent")
    cp_m25 = [
        c for c in m25_ord["calls"] if int(c.get("has_checkpoint", 0)) == 1
    ]
    if int(cp_m25[0]["cp_observed_c"]) != 1:
        return _fail_check(f"{m25_ord['id']}: cp_observed_c must be 1 (CUM)")

    m26_ord = p1b2_by_kind["mode26_cleanup_plan_present_still_ordinary_corrupt"]
    err = _p1b2_still_ordinary_common(
        m26_ord,
        mode=26,
        peer_gets=0,
        subject_kind=2,
        primary_subtype=0x20,  # ANCHOR
        forbid_subtype=0x52,  # MANAGEMENT
        model_fn=run_d3s2_mode26_cleanup_plan_still_ordinary_corrupt,
    )
    if err:
        return _fail_check(err)

    # ---- P1-C1 Mode23 illegal / equation / late ----
    p1c1_kinds_got = {v["kind"] for v in p1c1}
    if p1c1_kinds_got != D3S2_P1C1_KINDS:
        return _fail_check(f"p1c1 kinds inventory mismatch: {p1c1_kinds_got}")
    p1c1_by_kind = {v["kind"]: v for v in p1c1}

    def _p1c1_common(vec: Dict[str, Any], *, mode: int, peer_gets: int,
                     focus_live_flags: int, count_mask: int,
                     binding_mask: int,
                     require_state_anchor: bool = True,
                     require_corrupt: bool = True) -> Optional[str]:
        if int(vec["mode"]) != mode:
            return f"{vec['id']}: mode must be {mode}"
        if vec.get("ownership") != OWNERSHIP_P1C1:
            return f"{vec['id']}: ownership pin fail"
        if vec.get("faults"):
            return f"{vec['id']}: faults must be empty"
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return f"{vec['id']}: mutation_calls must be 0"
        if require_corrupt:
            if int(vec["expected"]["phase"]) != PHASE_FAILED:
                return f"{vec['id']}: phase must be FAILED"
            if vec["expected"]["final_status"] != "STORAGE_CORRUPT":
                return f"{vec['id']}: final_status must be STORAGE_CORRUPT"
            if int(vec["expected"]["has_sticky_primary"]) != 1:
                return f"{vec['id']}: sticky must be set"
            if vec["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
                return f"{vec['id']}: sticky_primary pin fail"
            if int(vec["expected"]["adopted"]) != 0:
                return f"{vec['id']}: adopted must be 0"
        else:
            if int(vec["expected"]["phase"]) != PHASE_COMPLETE:
                return f"{vec['id']}: phase must be COMPLETE"
            if vec["expected"]["final_status"] != "OK":
                return f"{vec['id']}: final_status must be OK"
            if int(vec["expected"]["has_sticky_primary"]) != 0:
                return f"{vec['id']}: sticky must be clear"
            if int(vec["expected"]["adopted"]) != 1:
                return f"{vec['id']}: adopted must be 1"
        if int(vec["expected"]["count_complete_mask"]) != count_mask:
            return (
                f"{vec['id']}: count_complete_mask must be {count_mask}, got "
                f"{vec['expected']['count_complete_mask']}"
            )
        if int(vec["expected"]["binding_complete_mask"]) != binding_mask:
            return (
                f"{vec['id']}: binding_complete_mask must be {binding_mask}"
            )
        if int(vec["expected"]["d3_peer_get_count"]) != peer_gets:
            return (
                f"{vec['id']}: d3_peer_get_count must be {peer_gets}, got "
                f"{vec['expected']['d3_peer_get_count']}"
            )
        if int(vec["expected"]["flags"]) != focus_live_flags:
            return (
                f"{vec['id']}: flags must be {focus_live_flags}, got "
                f"{vec['expected']['flags']}"
            )
        if (vec["expected"].get("port_trace") or []).count("begin:READ_ONLY") != 1:
            return f"{vec['id']}: single-txn begin pin fail"
        if require_corrupt:
            if vec["calls"][-1]["op"] != "abort":
                return f"{vec['id']}: fail path must end with abort"
        else:
            if vec["calls"][-1]["op"] != "finalize":
                return f"{vec['id']}: success path must end with finalize"
        if require_state_anchor:
            has_state = has_anchor = False
            for r in vec["rows"]:
                k = from_hex(r["key_hex"])
                if len(k) >= 10 and k[8] == 6 and k[9] == 0x22:
                    has_state = True
                if len(k) >= 10 and k[8] == 6 and k[9] == 0x20:
                    has_anchor = True
            if not has_state or not has_anchor:
                return f"{vec['id']}: must include STATE carrier + ANCHOR primary"
        return None

    m23_illegal = p1c1_by_kind["mode23_illegal_slot_L_plus_1_bind_corrupt"]
    err = _p1c1_common(
        m23_illegal,
        mode=23,
        peer_gets=4 + 8 + 1,  # FOCUS 0..L + BIND 4 legal * 2 + illegal carrier
        focus_live_flags=FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
        count_mask=MASK_EVIDENCE,
        binding_mask=0,
    )
    if err:
        return _fail_check(err)
    # Rebuild named from rows for independent model.
    named_il: Dict[str, Dict[str, str]] = {}
    for r in m23_illegal["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x32:
            _ck, _cs, slot, *_ = _parse_tx_evidence_cell(from_hex(r["value_hex"]))
            if slot == MODE23_ACCEPTED_L + 1:
                named_il["ev_slot_L_plus_1"] = r
            else:
                named_il[f"ev_slot{slot}"] = r
        elif len(k) >= 10 and k[8] == 6 and k[9] == 0x20:
            named_il["anchor"] = r
        elif len(k) >= 10 and k[8] == 6 and k[9] == 0x22:
            named_il["state"] = r
    try:
        exp_calls, exp_expected = run_d3s2_mode23_illegal_slot_L_plus_1_corrupt(
            m23_illegal["candidate_binding"],
            m23_illegal["rows"],
            named_il,
            MODE23_ACCEPTED_L,
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_illegal['id']}: model reject: {exc}")
    if m23_illegal["calls"] != exp_calls:
        return _fail_check(f"{m23_illegal['id']}: calls != independent model")
    if m23_illegal["expected"] != exp_expected:
        return _fail_check(f"{m23_illegal['id']}: expected != independent model")
    # Extra slot present and legal 0..L present.
    slots_present = set()
    for r in m23_illegal["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x32:
            _ck, _cs, slot, *_ = _parse_tx_evidence_cell(from_hex(r["value_hex"]))
            slots_present.add(int(slot))
    if set(range(0, MODE23_ACCEPTED_L + 1)) - slots_present:
        return _fail_check(f"{m23_illegal['id']}: missing required slots 0..L")
    if MODE23_ACCEPTED_L + 1 not in slots_present:
        return _fail_check(f"{m23_illegal['id']}: missing illegal L+1 row")

    m23_eq = p1c1_by_kind[
        "mode23_equation_fail_valid_ne_m_plus_overflow_corrupt"
    ]
    err = _p1c1_common(
        m23_eq,
        mode=23,
        peer_gets=MODE23_ACCEPTED_L + 1,
        focus_live_flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        count_mask=0,
        binding_mask=0,
    )
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = run_d3s2_mode23_focus_equation_or_late_corrupt(
            m23_eq["candidate_binding"],
            m23_eq["rows"],
            MODE23_ACCEPTED_L,
            kind_tag="equation-fail",
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_eq['id']}: model reject: {exc}")
    if m23_eq["calls"] != exp_calls:
        return _fail_check(f"{m23_eq['id']}: calls != independent model")
    if m23_eq["expected"] != exp_expected:
        return _fail_check(f"{m23_eq['id']}: expected != independent model")
    # Equation pin: valid != M + overflow with D1 domain ok.
    sum_row = None
    m_mat = 0
    for r in m23_eq["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x32:
            continue
        ck, cs, slot, _o, valid, overflow, late, lm = _parse_tx_evidence_cell(
            from_hex(r["value_hex"])
        )
        if slot == 0:
            sum_row = (valid, overflow, late, lm)
        elif (
            ck == EV_CELL_KIND_RAW
            and cs == EV_CELL_STATE_MATERIALIZED
            and 1 <= slot <= MODE23_ACCEPTED_L
        ):
            m_mat += 1
    if sum_row is None:
        return _fail_check(f"{m23_eq['id']}: SUMMARY missing")
    valid, overflow, late, lm = sum_row
    if overflow > valid or late > valid:
        return _fail_check(f"{m23_eq['id']}: SUMMARY must stay D1 counter-domain")
    if lm != (1 if late > 0 else 0):
        return _fail_check(f"{m23_eq['id']}: SUMMARY late_mat D1 fail")
    if valid == m_mat + overflow:
        return _fail_check(f"{m23_eq['id']}: must violate equation")

    m23_late = p1c1_by_kind[
        "mode23_late_coherence_observed_gt_declared_corrupt"
    ]
    err = _p1c1_common(
        m23_late,
        mode=23,
        peer_gets=MODE23_ACCEPTED_L + 1,
        focus_live_flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
        count_mask=0,
        binding_mask=0,
    )
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = run_d3s2_mode23_focus_equation_or_late_corrupt(
            m23_late["candidate_binding"],
            m23_late["rows"],
            MODE23_ACCEPTED_L,
            kind_tag="late-fail",
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_late['id']}: model reject: {exc}")
    if m23_late["calls"] != exp_calls:
        return _fail_check(f"{m23_late['id']}: calls != independent model")
    if m23_late["expected"] != exp_expected:
        return _fail_check(f"{m23_late['id']}: expected != independent model")
    sum_row = None
    m_mat = 0
    obs_late = 0
    for r in m23_late["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x32:
            continue
        ck, cs, slot, _o, valid, overflow, late, lm = _parse_tx_evidence_cell(
            from_hex(r["value_hex"])
        )
        if slot == 0:
            sum_row = (valid, overflow, late, lm)
        elif (
            ck == EV_CELL_KIND_RAW
            and cs == EV_CELL_STATE_MATERIALIZED
            and 1 <= slot <= MODE23_ACCEPTED_L
        ):
            m_mat += 1
            if lm != 0:
                obs_late += 1
    if sum_row is None:
        return _fail_check(f"{m23_late['id']}: SUMMARY missing")
    valid, overflow, late, lm = sum_row
    if valid != m_mat + overflow:
        return _fail_check(f"{m23_late['id']}: equation must stay green")
    if not (obs_late > late):
        return _fail_check(
            f"{m23_late['id']}: must have observed_c > declared_c "
            f"(obs={obs_late} decl={late})"
        )
    if lm != (1 if late > 0 else 0):
        return _fail_check(f"{m23_late['id']}: SUMMARY must stay D1 late_mat")
    # Forbid false late equality requirement in notes.
    notes_l = m23_late.get("notes") or ""
    if "requires declared_c == observed_c" in notes_l:
        return _fail_check(
            f"{m23_late['id']}: must not require declared_c==observed_c"
        )


    # ---- cancel slot0 / multi-owner success / multi-owner corrupt ----
    m23_cf = p1c1_by_kind["mode23_cancel_first_slot0_bind_corrupt"]
    err = _p1c1_common(
        m23_cf,
        mode=23,
        peer_gets=1,
        focus_live_flags=FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
        count_mask=MASK_EVIDENCE,
        binding_mask=0,
        require_state_anchor=False,
    )
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = run_d3s2_mode23_cancel_first_slot0_corrupt(
            m23_cf["candidate_binding"], m23_cf["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_cf['id']}: model reject: {exc}")
    if m23_cf["calls"] != exp_calls:
        return _fail_check(f"{m23_cf['id']}: calls != independent model")
    if m23_cf["expected"] != exp_expected:
        return _fail_check(f"{m23_cf['id']}: expected != independent model")
    has_rc = has_ev = False
    for r in m23_cf["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x41:
            has_rc = True
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x32:
            has_ev = True
    if not has_rc or not has_ev:
        return _fail_check(f"{m23_cf['id']}: need RC CANCEL + EVIDENCE")

    m23_mok = p1c1_by_kind["mode23_multi_owner_cancel_last_tx_ok"]
    err = _p1c1_common(
        m23_mok,
        mode=23,
        peer_gets=(MODE23_ACCEPTED_L + 1) + (MODE23_ACCEPTED_L + 1) * 2,
        focus_live_flags=FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
        count_mask=MASK_EVIDENCE,
        binding_mask=MASK_EVIDENCE,
        require_corrupt=False,
    )
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = run_d3s2_mode23_multi_owner_cancel_last_tx_ok(
            m23_mok["candidate_binding"], m23_mok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_mok['id']}: model reject: {exc}")
    if m23_mok["calls"] != exp_calls:
        return _fail_check(f"{m23_mok['id']}: calls != independent model")
    if m23_mok["expected"] != exp_expected:
        return _fail_check(f"{m23_mok['id']}: expected != independent model")
    # Carrier order STATE < RC and no CANCEL evidence.
    state_k = rc_k = None
    for r in m23_mok["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x22:
            state_k = k
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x41:
            rc_k = k
    if state_k is None or rc_k is None or not (state_k < rc_k):
        return _fail_check(f"{m23_mok['id']}: STATE must sort before RC CANCEL")

    m23_mc = p1c1_by_kind["mode23_multi_owner_tx_before_cancel_ev_corrupt"]
    err = _p1c1_common(
        m23_mc,
        mode=23,
        peer_gets=(MODE23_ACCEPTED_L + 1) + (MODE23_ACCEPTED_L + 1) * 2 + 1,
        focus_live_flags=FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
        count_mask=MASK_EVIDENCE,
        binding_mask=0,
    )
    if err:
        return _fail_check(err)
    try:
        exp_calls, exp_expected = (
            run_d3s2_mode23_multi_owner_tx_before_cancel_ev_corrupt(
                m23_mc["candidate_binding"], m23_mc["rows"]
            )
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_mc['id']}: model reject: {exc}")
    if m23_mc["calls"] != exp_calls:
        return _fail_check(f"{m23_mc['id']}: calls != independent model")
    if m23_mc["expected"] != exp_expected:
        return _fail_check(f"{m23_mc['id']}: expected != independent model")
    # TX EV keys before EV_DLV; STATE before RC.
    tx_keys = []
    ev_dlv_k = None
    state_k = rc_k = None
    for r in m23_mc["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6:
            continue
        if k[9] == 0x22:
            state_k = k
        elif k[9] == 0x41:
            rc_k = k
        elif k[9] == 0x32:
            # Distinguish TX vs DLV owner by body owner_kind
            try:
                _ck, _cs, slot, owner, *_rest = _parse_tx_evidence_cell(
                    from_hex(r["value_hex"])
                )
                tx_keys.append(k)
            except SystemExit:
                ev_dlv_k = k
    if state_k is None or rc_k is None or not (state_k < rc_k):
        return _fail_check(f"{m23_mc['id']}: STATE < RC pin fail")
    # EV_DLV is delivery-owned; parse TX may fail — detect via owner_kind
    tx_keys = []
    ev_dlv_k = None
    for r in m23_mc["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x32:
            continue
        st, body, _ = _d3s1.extract_envelope(from_hex(r["value_hex"]))
        import struct as _struct
        owner_kind = _struct.unpack_from(">H", body, 0)[0]
        if owner_kind == EV_OWNER_KIND_TX:
            tx_keys.append(k)
        else:
            ev_dlv_k = k
    if ev_dlv_k is None or not tx_keys:
        return _fail_check(f"{m23_mc['id']}: need TX EV + EV_DLV")
    if not all(tk < ev_dlv_k for tk in tx_keys):
        return _fail_check(f"{m23_mc['id']}: TX EV keys must sort before EV_DLV")

    # ---- P1-C2 Mode24/25 known-slot population legality (case3 residual) ----
    p1c2_kinds_got = {v["kind"] for v in p1c2}
    if p1c2_kinds_got != D3S2_P1C2_KINDS:
        return _fail_check(f"p1c2 kinds inventory mismatch: {p1c2_kinds_got}")
    p1c2_by_kind = {v["kind"]: v for v in p1c2}

    def _p1c2_common(
        vec: Dict[str, Any],
        *,
        mode: int,
        peer_gets: int,
        domain_n: int,
        obs_a: int,
        obs_c: int,
        model_fn,
    ) -> Optional[str]:
        if int(vec["mode"]) != mode:
            return f"{vec['id']}: mode must be {mode}"
        if vec.get("ownership") != OWNERSHIP_P1C2:
            return f"{vec['id']}: ownership pin fail"
        if vec.get("faults"):
            return f"{vec['id']}: faults must be empty"
        exp = vec["expected"]
        if exp.get("final_status") != "STORAGE_CORRUPT":
            return f"{vec['id']}: final_status must be STORAGE_CORRUPT"
        if int(exp.get("phase", -1)) != PHASE_FAILED:
            return f"{vec['id']}: phase must be FAILED"
        if int(exp.get("has_sticky_primary", -1)) != 1:
            return f"{vec['id']}: sticky must be set"
        if exp.get("sticky_primary") != "STORAGE_CORRUPT":
            return f"{vec['id']}: sticky_primary pin fail"
        if int(exp.get("adopted", -1)) != 0:
            return f"{vec['id']}: adopted must be 0"
        if int(exp.get("mutation_calls", -1)) != 0:
            return f"{vec['id']}: mutation_calls must be 0"
        if int(exp.get("count_complete_mask", -1)) != 0:
            return f"{vec['id']}: count_complete_mask must be 0 (FOCUS fail)"
        if int(exp.get("binding_complete_mask", -1)) != 0:
            return f"{vec['id']}: binding_complete_mask must be 0"
        if int(exp.get("d3_peer_get_count", -1)) != peer_gets:
            return (
                f"{vec['id']}: d3_peer_get_count must be {peer_gets}, got "
                f"{exp.get('d3_peer_get_count')}"
            )
        if int(exp.get("d3_mode_applicable_count", -1)) != 0:
            return f"{vec['id']}: d3_mode_applicable_count must be 0 (no BIND)"
        if int(exp.get("current_domain_key_count", -1)) != domain_n:
            return (
                f"{vec['id']}: current_domain_key_count must be {domain_n}"
            )
        if int(exp.get("flags", -1)) != (
            FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE
        ):
            return f"{vec['id']}: flags must keep FOCUS_LIVE after note"
        pt = exp.get("port_trace") or []
        if pt.count("begin:READ_ONLY") != 1:
            return f"{vec['id']}: single-txn begin pin fail"
        if pt.count("get") != 17 + peer_gets:
            return (
                f"{vec['id']}: get budget must be 17+{peer_gets}, got "
                f"{pt.count('get')}"
            )
        if vec["calls"][-1]["op"] != "abort":
            return f"{vec['id']}: fail path must end with abort"
        cps = [c for c in vec["calls"] if int(c.get("has_checkpoint", 0)) == 1]
        if len(cps) != 1:
            return f"{vec['id']}: exact 1 checkpoint required"
        cp = cps[0]
        if int(cp.get("cp_cleanup_skip", -1)) != 0:
            return f"{vec['id']}: cleanup_skip must be 0"
        if int(cp.get("cp_phase", -1)) != PHASE_FAILED:
            return f"{vec['id']}: checkpoint phase must be FAILED"
        if int(cp.get("cp_focus_live", -1)) != 1:
            return f"{vec['id']}: checkpoint focus_live must be 1"
        if int(cp.get("cp_observed_a", -1)) != obs_a:
            return (
                f"{vec['id']}: cp_observed_a must be {obs_a}, got "
                f"{cp.get('cp_observed_a')}"
            )
        if int(cp.get("cp_observed_c", -1)) != obs_c:
            return (
                f"{vec['id']}: cp_observed_c must be {obs_c}, got "
                f"{cp.get('cp_observed_c')}"
            )
        if int(cp.get("cp_begin_calls", -1)) != 1:
            return f"{vec['id']}: cp_begin_calls must be 1"
        try:
            exp_calls, exp_expected = model_fn(
                vec["candidate_binding"], vec["rows"]
            )
        except SystemExit as exc:
            return f"{vec['id']}: model reject: {exc}"
        if vec["calls"] != exp_calls:
            return f"{vec['id']}: calls != independent model"
        if vec["expected"] != exp_expected:
            return f"{vec['id']}: expected != independent model"
        return None

    m24_miss = p1c2_by_kind[
        "mode24_rc_reply1_empty_secondary_undercount_corrupt"
    ]
    err = _p1c2_common(
        m24_miss,
        mode=24,
        peer_gets=4,
        domain_n=2,
        obs_a=0,
        obs_c=0,
        model_fn=run_d3s2_mode24_reply_empty_secondary_undercount_corrupt,
    )
    if err:
        return _fail_check(err)
    rr_n = sum(
        1
        for r in m24_miss["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x42
    )
    if rr_n != 0:
        return _fail_check(f"{m24_miss['id']}: must ship zero REVERSE_REPLY")

    m24_extra = p1c2_by_kind[
        "mode24_rc_reply1_extra_disposition_overcount_corrupt"
    ]
    err = _p1c2_common(
        m24_extra,
        mode=24,
        peer_gets=4,
        domain_n=4,
        obs_a=2,
        obs_c=0,
        model_fn=run_d3s2_mode24_reply_extra_disposition_overcount_corrupt,
    )
    if err:
        return _fail_check(err)
    kinds_rr = []
    for r in m24_extra["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x42:
            kinds_rr.append(
                _parse_rr_kind_and_delivery(from_hex(r["value_hex"]))[0]
            )
    if sorted(kinds_rr) != [RR_KIND_RECEIPT, RR_KIND_DISPOSITION]:
        return _fail_check(
            f"{m24_extra['id']}: must ship RECEIPT+DISPOSITION only, got "
            f"{kinds_rr}"
        )
    # Anti-pass: both kinds in closed D1 domain (not fabricated kind 0/5).
    if any(k < RR_KIND_MIN or k > RR_KIND_MAX for k in kinds_rr):
        return _fail_check(f"{m24_extra['id']}: RR kinds must stay in 1..4")

    m25_miss = p1c2_by_kind[
        "mode25_cum_total1_recent_missing_undercount_corrupt"
    ]
    err = _p1c2_common(
        m25_miss,
        mode=25,
        peer_gets=5,
        domain_n=2,
        obs_a=0,
        obs_c=1,
        model_fn=run_d3s2_mode25_recent_missing_undercount_corrupt,
    )
    if err:
        return _fail_check(err)
    rec_n = 0
    for r in m25_miss["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x51:
            continue
        _tx, kind, _slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if kind == RS_KIND_RECENT:
            rec_n += 1
    if rec_n != 0:
        return _fail_check(f"{m25_miss['id']}: must ship zero RECENT")

    m25_extra = p1c2_by_kind[
        "mode25_cum_total1_recent_extra_slot_overcount_corrupt"
    ]
    err = _p1c2_common(
        m25_extra,
        mode=25,
        peer_gets=5,
        domain_n=4,
        obs_a=2,
        obs_c=1,
        model_fn=run_d3s2_mode25_recent_extra_slot_overcount_corrupt,
    )
    if err:
        return _fail_check(err)
    rec_slots = []
    for r in m25_extra["rows"]:
        k = from_hex(r["key_hex"])
        if len(k) < 10 or k[8] != 6 or k[9] != 0x51:
            continue
        _tx, kind, slot = _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
        if kind == RS_KIND_RECENT:
            if slot > 3:
                return _fail_check(
                    f"{m25_extra['id']}: RECENT slot must stay D1-legal <=3"
                )
            rec_slots.append(int(slot))
            # D1 slot arithmetic vs cycle
            _st, body, _ = _d3s1.extract_envelope(from_hex(r["value_hex"]))
            cycle = struct.unpack_from(">Q", body, 20)[0]
            if int(slot) != (int(cycle) - 1) % 4:
                return _fail_check(
                    f"{m25_extra['id']}: RECENT slot!=(cycle-1)mod4"
                )
    if sorted(rec_slots) != [0, 1]:
        return _fail_check(
            f"{m25_extra['id']}: RECENT slots must be {{0,1}}, got {rec_slots}"
        )

    if not D3S2_REQUIRED_KINDS.issubset(kinds):
        return _fail_check(
            f"missing d3s2 kinds {D3S2_REQUIRED_KINDS - kinds}"
        )

    # Full rebuild equality (canonical document).
    if data.get("content_sha256") != expected_doc.get("content_sha256"):
        return _fail_check("content_sha256 rebuild mismatch")
    if data.get("prior_fingerprints") != expected_doc.get("prior_fingerprints"):
        return _fail_check("prior_fingerprints rebuild mismatch")
    # Vectors deep equality via content hash is sufficient; also pin suffix fps.
    for i in range(D3S1_PREFIX_COUNT, EXPECTED_VECTOR_COUNT):
        if d3s2_vector_fingerprint(vectors[i]) != exp_fps[i]["fingerprint"]:
            return _fail_check(f"suffix fingerprint rebuild fail at {i}")

    print(
        f"ok {path} vectors={len(vectors)} "
        f"(d3s1_prefix={D3S1_PREFIX_COUNT} d3s2_suffix={D3S2_SUFFIX_COUNT}) "
        f"content_sha256={data.get('content_sha256')}"
    )
    return 0



def _p0b_focus_ok_end(port_trace: List[str]) -> int:
    """Index just after last FOCUS OK iter_next under P0-B budget stop model."""
    open_idxs = [i for i, t in enumerate(port_trace) if t == "iter_open:prefix0"]
    if len(open_idxs) < 3:
        raise SystemExit("p0b focus open not found for self-test helper")
    # third open is FOCUS; n_ok=20 fixed for Mode26 success material
    return open_idxs[2] + 1 + 20


def self_test() -> int:
    """Negative self-tests that must FAIL check when applied to temp mutations."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        clean = root / "clean.json"
        generate(clean)
        # One independent generate+check (full rebuild) to prove the clean
        # artifact. Then freeze read-only expected/prefix for all tampers so
        # check does not re-run build_document/freeze_d3s1_prefix each time.
        if check(clean) != 0:
            print("self-test: clean generate+check failed", file=sys.stderr)
            return 1
        expected_doc = build_document()
        prefix_doc = freeze_d3s1_prefix()
        expected_doc_canary = hashlib.sha256(
            json.dumps(
                expected_doc, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).digest()
        prefix_doc_canary = hashlib.sha256(
            json.dumps(
                prefix_doc, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).digest()
        if check(clean, _expected_doc=expected_doc) == 0:
            print(
                "self-test: unpaired expected_doc injection accepted",
                file=sys.stderr,
            )
            return 1
        if check(clean, _prefix_doc=prefix_doc) == 0:
            print(
                "self-test: unpaired prefix_doc injection accepted",
                file=sys.stderr,
            )
            return 1
        # Re-validate clean via the injected path (same acceptance criteria).
        if (
            check(
                clean,
                _expected_doc=expected_doc,
                _prefix_doc=prefix_doc,
            )
            != 0
        ):
            print(
                "self-test: clean check with injected expected/prefix failed",
                file=sys.stderr,
            )
            return 1

        # Historical D3-S1 generator must not downgrade the shared append-only
        # artifact after it has advanced to the D3-S2 format.
        try:
            _d3s1.generate(clean)
        except SystemExit as exc:
            if "refusing D3-S2 sibling downgrade" not in str(exc):
                print(f"self-test: unexpected downgrade error: {exc}", file=sys.stderr)
                return 1
        else:
            print("self-test: D3-S1 generator accepted D3-S2 downgrade", file=sys.stderr)
            return 1

        def mut(name: str, fn) -> Optional[str]:
            p = root / f"{name}.json"
            # Independent deep load from clean JSON — never mutate expected_doc
            # / prefix_doc or share the clean in-memory tree across tampers.
            data = json.loads(clean.read_text(encoding="utf-8"))
            fn(data)
            p.write_text(
                json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            rc = check(
                p,
                _expected_doc=expected_doc,
                _prefix_doc=prefix_doc,
            )
            if rc == 0:
                return f"self-test {name}: expected check failure, got pass"
            return None

        failures: List[str] = []

        def t(name: str, fn) -> None:
            err = mut(name, fn)
            if err:
                failures.append(err)

        t(
            "format_fork",
            lambda d: d.__setitem__("format", "ninlil-domain-scan-crossrow-v1-d3s1"),
        )
        t(
            "vector_count_pin",
            lambda d: d.__setitem__("vector_count", 94),
        )
        t(
            "prefix_row_tamper",
            lambda d: d["vectors"][0]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "prefix_expected_tamper",
            lambda d: d["vectors"][0]["expected"].__setitem__("ok_row_count", 999),
        )
        t(
            "prefix_call_tamper",
            lambda d: d["vectors"][0]["calls"][0].__setitem__(
                "op", "begin_profiled_d3s2"
            ),
        )
        # 100-prefix freeze (smoke Mode21 + last smoke Mode26).
        t(
            "hundred_prefix_row_tamper",
            lambda d: d["vectors"][99]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_prefix_expected_tamper",
            lambda d: d["vectors"][94]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_prefix_fp_authority_tamper",
            lambda d: d["d3s2_100_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "suffix_mode_order",
            lambda d: d["vectors"][94].__setitem__("mode", 22),
        )
        t(
            "suffix_bind_mask",
            lambda d: d["vectors"][94]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "six_mode_single_session",
            lambda d: d["vectors"][94]["calls"].__setitem__(
                0,
                {
                    "op": "begin_profiled_d3s2",
                    "mode": 22,
                    "expected_status": "OK",
                },
            ),
        )
        t(
            "mutation_nonzero",
            lambda d: d["vectors"][95]["expected"].__setitem__("mutation_calls", 1),
        )
        t(
            "forbidden_begin",
            lambda d: d["vectors"][96]["calls"].insert(
                0, {"op": "begin", "expected_status": "OK"}
            ),
        )
        # New Mode25 slice tampers (indices 100, 101).
        t(
            "mode25_ok_count_mask_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode25_ok_bind_mask_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode25_ok_carrier_row_tamper",
            lambda d: d["vectors"][100]["rows"].pop(),
        )
        t(
            "mode25_ok_trace_tamper",
            lambda d: d["vectors"][100]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode25_ok_mutation_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        t(
            "mode25_bad_count_mask_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "count_complete_mask", MASK_RETRY
            ),
        )
        t(
            "mode25_bad_bind_mask_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "binding_complete_mask", MASK_RETRY
            ),
        )
        t(
            "mode25_bad_carrier_insert_tamper",
            lambda d: d["vectors"][101]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode25_bad_trace_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode25_bad_mutation_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        t(
            "mode25_bad_sticky_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        # 102-prefix freeze (includes Mode25; Mode26 follows at 102+).
        t(
            "hundred_two_prefix_row_tamper",
            lambda d: d["vectors"][101]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_two_prefix_expected_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_two_prefix_fp_authority_tamper",
            lambda d: d["d3s2_102_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_two_prefix_content_authority_tamper",
            lambda d: d["d3s2_102_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # New Mode26 slice tampers (indices 102, 103).
        t(
            "mode26_ok_count_mask_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode26_ok_bind_mask_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode26_ok_carrier_row_tamper",
            lambda d: d["vectors"][102]["rows"].pop(),
        )
        t(
            "mode26_ok_trace_tamper",
            lambda d: d["vectors"][102]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode26_ok_pvd_row_tamper",
            lambda d: d["vectors"][102]["rows"].__setitem__(
                -1,
                {
                    "key_hex": d["vectors"][102]["rows"][-1]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode26_ok_mutation_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        t(
            "mode26_bad_count_mask_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "count_complete_mask", MASK_MANAGEMENT
            ),
        )
        t(
            "mode26_bad_bind_mask_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "binding_complete_mask", MASK_MANAGEMENT
            ),
        )
        t(
            "mode26_bad_carrier_insert_tamper",
            lambda d: d["vectors"][103]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode26_bad_trace_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode26_bad_sticky_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode26_bad_mutation_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 104-prefix freeze (includes Mode25+Mode26; Mode24 follows at 104+).
        t(
            "hundred_four_prefix_row_tamper",
            lambda d: d["vectors"][103]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_four_prefix_expected_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_four_prefix_fp_authority_tamper",
            lambda d: d["d3s2_104_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_four_prefix_content_authority_tamper",
            lambda d: d["d3s2_104_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # New Mode24 success tampers (index 104): reply_count/popcount/
        # count-mask/bind/PVD/trace/mutation.
        t(
            "mode24_ok_reply_count_row_tamper",
            lambda d: d["vectors"][104]["rows"].__setitem__(
                -2,
                {
                    "key_hex": d["vectors"][104]["rows"][-2]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode24_ok_count_mask_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode24_ok_bind_mask_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode24_ok_peer_get_popcount_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode24_ok_pvd_row_tamper",
            lambda d: d["vectors"][104]["rows"].__setitem__(
                -1,
                {
                    "key_hex": d["vectors"][104]["rows"][-1]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode24_ok_trace_tamper",
            lambda d: d["vectors"][104]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode24_ok_mutation_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode24 orphan tampers (index 105): carrier/trace/sticky/mutation.
        t(
            "mode24_bad_count_mask_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "count_complete_mask", MASK_REPLY
            ),
        )
        t(
            "mode24_bad_bind_mask_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "binding_complete_mask", MASK_REPLY
            ),
        )
        t(
            "mode24_bad_carrier_insert_tamper",
            lambda d: d["vectors"][105]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode24_bad_trace_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode24_bad_sticky_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode24_bad_mutation_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 106-prefix freeze (includes Mode25+Mode26+Mode24; Mode23 at 106+).
        t(
            "hundred_six_prefix_row_tamper",
            lambda d: d["vectors"][105]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_six_prefix_expected_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_six_prefix_fp_authority_tamper",
            lambda d: d["d3s2_106_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_six_prefix_content_authority_tamper",
            lambda d: d["d3s2_106_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # Ownership must remain frozen 12-vector text on the 106-prefix
        # (append-only; Mode23 must not rewrite prior objects).
        t(
            "hundred_six_prefix_ownership_tamper",
            lambda d: d["vectors"][105].__setitem__(
                "ownership", OWNERSHIP_MODE23
            ),
        )
        # New Mode23 success tampers (index 106): equation/mask/PVD/trace.
        t(
            "mode23_ok_count_mask_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode23_ok_bind_mask_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode23_ok_peer_get_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode23_ok_equation_row_tamper",
            lambda d: d["vectors"][106]["rows"].pop(),
        )
        t(
            "mode23_ok_pvd_row_tamper",
            lambda d: d["vectors"][106]["rows"].__setitem__(
                -1,
                {
                    "key_hex": d["vectors"][106]["rows"][-1]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode23_ok_trace_tamper",
            lambda d: d["vectors"][106]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode23_ok_mutation_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode23 orphan tampers (index 107): carrier/trace/sticky/mutation.
        t(
            "mode23_bad_count_mask_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "count_complete_mask", MASK_EVIDENCE
            ),
        )
        t(
            "mode23_bad_bind_mask_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "binding_complete_mask", MASK_EVIDENCE
            ),
        )
        t(
            "mode23_bad_carrier_insert_tamper",
            lambda d: d["vectors"][107]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode23_bad_trace_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode23_bad_sticky_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode23_bad_mutation_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 108-prefix freeze (includes Mode25+Mode26+Mode24+Mode23; Mode22 at 108+).
        t(
            "hundred_eight_prefix_row_tamper",
            lambda d: d["vectors"][107]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_eight_prefix_expected_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_eight_prefix_fp_authority_tamper",
            lambda d: d["d3s2_108_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_eight_prefix_content_authority_tamper",
            lambda d: d["d3s2_108_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # Ownership must remain frozen 14-vector text on the 108-prefix
        # (append-only; Mode22 must not rewrite prior Mode23 objects).
        t(
            "hundred_eight_prefix_ownership_tamper",
            lambda d: d["vectors"][107].__setitem__(
                "ownership", OWNERSHIP_MODE22
            ),
        )
        # New Mode22 success tampers (index 108): mask/peer/INDEX/trace/mutation.
        t(
            "mode22_ok_count_mask_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode22_ok_bind_mask_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode22_ok_peer_get_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode22_ok_index_mask_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT | MASK_INDEX
            ),
        )
        t(
            "mode22_ok_unexpected_index_row_tamper",
            lambda d: d["vectors"][108]["rows"].append(
                {"key_hex": "00" * 45, "value_hex": "00" * 32}
            ),
        )
        t(
            "mode22_ok_trace_tamper",
            lambda d: d["vectors"][108]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode22_ok_mutation_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode22 orphan tampers (index 109): carrier/trace/sticky/mutation.
        t(
            "mode22_bad_count_mask_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "count_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode22_bad_bind_mask_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode22_bad_carrier_insert_tamper",
            lambda d: d["vectors"][109]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode22_bad_peer_get_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "d3_peer_get_count", 3
            ),
        )
        t(
            "mode22_bad_trace_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode22_bad_sticky_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode22_bad_mutation_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 110-prefix freeze (includes Mode25+..+Mode22; Mode21 at 110+).
        t(
            "hundred_ten_prefix_row_tamper",
            lambda d: d["vectors"][109]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_ten_prefix_expected_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_ten_prefix_fp_authority_tamper",
            lambda d: d["d3s2_110_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_ten_prefix_content_authority_tamper",
            lambda d: d["d3s2_110_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # Ownership must remain frozen 16-vector text on the 110-prefix
        # (append-only; Mode21 must not rewrite prior Mode22 objects).
        t(
            "hundred_ten_prefix_ownership_tamper",
            lambda d: d["vectors"][109].__setitem__(
                "ownership", OWNERSHIP_MODE21
            ),
        )
        # New Mode21 success tampers (index 110): mask/peer/INDEX/trace/mutation.
        t(
            "mode21_ok_count_mask_tamper",
            lambda d: d["vectors"][110]["expected"].__setitem__(
                "count_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode21_ok_bind_mask_tamper",
            lambda d: d["vectors"][110]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode21_ok_peer_get_tamper",
            lambda d: d["vectors"][110]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode21_ok_index_drop_tamper",
            lambda d: d["vectors"][110]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode21_ok_aii_row_drop_tamper",
            lambda d: d["vectors"][110].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][110]["rows"]
                    if not (
                        len(from_hex(r["key_hex"])) >= 10
                        and from_hex(r["key_hex"])[8] == 6
                        and from_hex(r["key_hex"])[9] == 0x34
                    )
                ],
            ),
        )
        t(
            "mode21_ok_trace_tamper",
            lambda d: d["vectors"][110]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode21_ok_mutation_tamper",
            lambda d: d["vectors"][110]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode21 pair-absent tampers (index 111).
        t(
            "mode21_bad_count_mask_tamper",
            lambda d: d["vectors"][111]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode21_bad_bind_mask_tamper",
            lambda d: d["vectors"][111]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT | MASK_INDEX
            ),
        )
        t(
            "mode21_bad_aii_insert_tamper",
            lambda d: d["vectors"][111]["rows"].append(
                {"key_hex": "00" * 29, "value_hex": "00" * 32}
            ),
        )
        t(
            "mode21_bad_peer_get_tamper",
            lambda d: d["vectors"][111]["expected"].__setitem__(
                "d3_peer_get_count", 1
            ),
        )
        t(
            "mode21_bad_trace_tamper",
            lambda d: d["vectors"][111]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode21_bad_sticky_tamper",
            lambda d: d["vectors"][111]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode21_bad_mutation_tamper",
            lambda d: d["vectors"][111]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 112-prefix freeze (includes Mode21; P0-A at 112).
        t(
            "hundred_twelve_prefix_row_tamper",
            lambda d: d["vectors"][111]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_twelve_prefix_expected_tamper",
            lambda d: d["vectors"][110]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_twelve_prefix_fp_authority_tamper",
            lambda d: d["d3s2_112_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_twelve_prefix_content_authority_tamper",
            lambda d: d["d3s2_112_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        t(
            "hundred_twelve_prefix_ownership_tamper",
            lambda d: d["vectors"][111].__setitem__(
                "ownership", OWNERSHIP_P0A
            ),
        )
        # P0-A multi-owner tampers (index 112).
        t(
            "p0a_ok_count_mask_tamper",
            lambda d: d["vectors"][112]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "p0a_ok_bind_mask_tamper",
            lambda d: d["vectors"][112]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "p0a_ok_peer_get_tamper",
            lambda d: d["vectors"][112]["expected"].__setitem__(
                "d3_peer_get_count", 8
            ),
        )
        t(
            "p0a_ok_trace_tamper",
            lambda d: d["vectors"][112]["expected"]["port_trace"].append("put"),
        )
        t(
            "p0a_ok_mutation_tamper",
            lambda d: d["vectors"][112]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # Owner interleave destroy: drop one owner's RECENT (breaks ABAB + count).
        t(
            "p0a_owner_interleave_destroy_tamper",
            lambda d: d["vectors"][112].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][112]["rows"]
                    if not (
                        len(from_hex(r["key_hex"])) >= 10
                        and from_hex(r["key_hex"])[8] == 6
                        and from_hex(r["key_hex"])[9] == 0x51
                        and _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
                        == (MODE25_MULTI_TX_B, RS_KIND_RECENT, 0)
                    )
                ],
            ),
        )
        # Contiguous-owner force: not directly reorderable without full rekey;
        # drop CUM_B so carrier select cannot complete dual-carrier path.
        t(
            "p0a_carrier_delete_tamper",
            lambda d: d["vectors"][112].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][112]["rows"]
                    if not (
                        len(from_hex(r["key_hex"])) >= 10
                        and from_hex(r["key_hex"])[8] == 6
                        and from_hex(r["key_hex"])[9] == 0x51
                        and _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
                        == (MODE25_MULTI_TX_B, RS_KIND_CUMULATIVE, 0)
                    )
                ],
            ),
        )
        # Carrier duplicate: append a second copy of CUM_A row (key/value).
        t(
            "p0a_carrier_dup_tamper",
            lambda d: d["vectors"][112]["rows"].append(
                copy.deepcopy(
                    next(
                        r
                        for r in d["vectors"][112]["rows"]
                        if len(from_hex(r["key_hex"])) >= 10
                        and from_hex(r["key_hex"])[8] == 6
                        and from_hex(r["key_hex"])[9] == 0x51
                        and _parse_retry_tx_kind_slot(from_hex(r["value_hex"]))
                        == (MODE25_MULTI_TX_A, RS_KIND_CUMULATIVE, 0)
                    )
                )
            ),
        )
        t(
            "p0a_get_count_trace_tamper",
            lambda d: d["vectors"][112]["expected"].__setitem__(
                "port_trace",
                [x for x in d["vectors"][112]["expected"]["port_trace"] if x != "get"]
                + ["get"] * 17,  # baseline-only gets; peer gets wiped
            ),
        )
        # 113-prefix freeze (includes P0-A; P0-B at 113).
        t(
            "hundred_thirteen_prefix_row_tamper",
            lambda d: d["vectors"][112]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_thirteen_prefix_expected_tamper",
            lambda d: d["vectors"][112]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_thirteen_prefix_fp_authority_tamper",
            lambda d: d["d3s2_113_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_thirteen_prefix_content_authority_tamper",
            lambda d: d["d3s2_113_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        t(
            "hundred_thirteen_prefix_ownership_tamper",
            lambda d: d["vectors"][112].__setitem__(
                "ownership", OWNERSHIP_P0B
            ),
        )
        # P0-B budget mid-focus resume tampers (index 113).
        t(
            "p0b_checkpoint_phase_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("cp_phase", PHASE_COMPLETE),
        )
        t(
            "p0b_checkpoint_focus_live_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("cp_focus_live", 0),
        )
        t(
            "p0b_checkpoint_observed_a_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("cp_observed_a", 0),
        )
        t(
            "p0b_checkpoint_count_mask_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("cp_count_complete_mask", MASK_MANAGEMENT),
        )
        t(
            "p0b_checkpoint_begin_calls_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("cp_begin_calls", 2),
        )
        t(
            "p0b_budget_19_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("row_budget", 19),
        )
        t(
            "p0b_budget_21_tamper",
            lambda d: next(
                c
                for c in d["vectors"][113]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ).__setitem__("row_budget", 21),
        )
        def _tamper_p0b_mid_boundary(d):
            pt = list(d["vectors"][113]["expected"]["port_trace"])
            end = _p0b_focus_ok_end(pt)
            d["vectors"][113]["expected"]["port_trace"] = (
                pt[:end] + ["iter_close", "iter_open:prefix0"] + pt[end:]
            )

        t("p0b_mid_boundary_iter_reopen_tamper", _tamper_p0b_mid_boundary)
        t(
            "p0b_ok_phase_final_tamper",
            lambda d: d["vectors"][113]["expected"].__setitem__(
                "phase", PHASE_FAILED
            ),
        )
        t(
            "p0b_ok_mutation_tamper",
            lambda d: d["vectors"][113]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # 114-prefix freeze (includes P0-B; P0-C at 114).
        t(
            "hundred_fourteen_prefix_row_tamper",
            lambda d: d["vectors"][113]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_fourteen_prefix_expected_tamper",
            lambda d: d["vectors"][113]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_fourteen_prefix_fp_authority_tamper",
            lambda d: d["d3s2_114_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_fourteen_prefix_content_authority_tamper",
            lambda d: d["d3s2_114_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        t(
            "hundred_fourteen_prefix_ownership_tamper",
            lambda d: d["vectors"][113].__setitem__(
                "ownership", OWNERSHIP_P0C
            ),
        )
        # P0-C Port BIND note0 tampers (index 114).
        t(
            "p0c_sticky_corrupt_tamper",
            lambda d: d["vectors"][114]["expected"].__setitem__(
                "sticky_primary", "STORAGE_CORRUPT"
            ),
        )
        t(
            "p0c_note_count_tamper",
            lambda d: d["vectors"][114]["expected"].__setitem__(
                "note_count", 1
            ),
        )
        t(
            "p0c_final_status_tamper",
            lambda d: d["vectors"][114]["expected"].__setitem__(
                "final_status", "STORAGE_CORRUPT"
            ),
        )
        t(
            "p0c_fault_on_call_tamper",
            lambda d: d["vectors"][114]["faults"][0].__setitem__(
                "on_call", 1
            ),
        )
        t(
            "p0c_count_mask_zero_tamper",
            lambda d: d["vectors"][114]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "p0c_bind_mask_green_tamper",
            lambda d: d["vectors"][114]["expected"].__setitem__(
                "binding_complete_mask", MASK_RETRY
            ),
        )
        t(
            "p0c_mutation_tamper",
            lambda d: d["vectors"][114]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # Two-txn list-then-count anti-pass: insert second begin between
        # FOCUS and BIND on Mode25 success while claiming COMPLETE.
        def _two_txn_list_count_split(d):
            # Index 100 = Mode25 CUM success (formal single-txn COMPLETE).
            pt = list(d["vectors"][100]["expected"]["port_trace"] )
            # Insert second begin after first full walk close (list txn end)
            # and before next iter_open (count/BIND txn start).
            try:
                first_close = pt.index("iter_close")
            except ValueError:
                first_close = 20
            d["vectors"][100]["expected"]["port_trace"] = (
                pt[: first_close + 1]
                + ["begin:READ_ONLY"]
                + pt[first_close + 1 :]
            )

        t("two_txn_list_count_port_trace_tamper", _two_txn_list_count_split)
        # Also reject COMPLETE smoke when port_trace claims two begins.
        def _two_txn_smoke(d):
            pt = list(d["vectors"][94]["expected"]["port_trace"])
            d["vectors"][94]["expected"]["port_trace"] = (
                pt[:1] + ["begin:READ_ONLY"] + pt[1:]
            )

        t("two_txn_smoke_begin_double_tamper", _two_txn_smoke)
        # 119-prefix freeze (includes P0-D; P1-A at 119+).
        t(
            "hundred_nineteen_prefix_row_tamper",
            lambda d: d["vectors"][118]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_nineteen_prefix_expected_tamper",
            lambda d: d["vectors"][118]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_nineteen_prefix_fp_authority_tamper",
            lambda d: d["d3s2_119_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_nineteen_prefix_content_authority_tamper",
            lambda d: d["d3s2_119_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-A stream count failure tampers (indices 119..124).
        t(
            "p1a_app_over_status_ok_tamper",
            lambda d: d["vectors"][119]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1a_app_over_count_mask_tamper",
            lambda d: d["vectors"][119]["expected"].__setitem__(
                "count_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "p1a_index_under_cleanup_insert_tamper",
            lambda d: d["vectors"][121]["rows"].append(
                {"key_hex": "00" * 45, "value_hex": "00" * 32}
            ),
        )
        t(
            "p1a_index_under_count_mask_zero_tamper",
            lambda d: d["vectors"][121]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "p1a_m22_app_peer_get_tamper",
            lambda d: d["vectors"][122]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "p1a_m26_over_peer_get_tamper",
            lambda d: d["vectors"][124]["expected"].__setitem__(
                "d3_peer_get_count", 2
            ),
        )
        t(
            "p1a_m26_over_mutation_tamper",
            lambda d: d["vectors"][124]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        t(
            "p1a_ownership_tamper",
            lambda d: d["vectors"][119].__setitem__(
                "ownership", OWNERSHIP_P0D
            ),
        )
        # 125-prefix freeze (includes P1-A; P1-D follows at 125+).
        t(
            "hundred_twenty_five_prefix_row_tamper",
            lambda d: d["vectors"][124]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_twenty_five_prefix_expected_tamper",
            lambda d: d["vectors"][119]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_twenty_five_prefix_fp_authority_tamper",
            lambda d: d["d3s2_125_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_twenty_five_prefix_content_authority_tamper",
            lambda d: d["d3s2_125_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-D evaluator-off anti-pass (indices 125, 126).
        t(
            "p1d_mismatch_complete_ready_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "flags", FLAG_BASELINE_DONE | FLAG_COMPLETE_READY
            ),
        )
        t(
            "p1d_mismatch_phase_complete_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "phase", PHASE_COMPLETE
            ),
        )
        t(
            "p1d_mismatch_internal_reopen_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "iter_open_count", 2
            ),
        )
        t(
            "p1d_mismatch_port_trace_second_open_tamper",
            lambda d: d["vectors"][125]["expected"]["port_trace"].insert(
                -1, "iter_open:prefix0"
            ),
        )
        t(
            "p1d_mismatch_bind_mask_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT | MASK_INDEX
            ),
        )
        t(
            "p1d_mismatch_peer_get_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "d3_peer_get_count", 1
            ),
        )
        t(
            "p1d_mismatch_adopt1_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__("adopted", 1),
        )
        t(
            "p1d_mismatch_post_open_get_tamper",
            lambda d: d["vectors"][125]["expected"]["port_trace"].insert(
                d["vectors"][125]["expected"]["port_trace"].index(
                    "iter_open:prefix0"
                )
                + 2,
                "get",
            ),
        )
        t(
            "p1d_future_complete_ready_tamper",
            lambda d: d["vectors"][126]["expected"].__setitem__(
                "flags", FLAG_BASELINE_DONE | FLAG_COMPLETE_READY
            ),
        )
        t(
            "p1d_future_bind_mask_tamper",
            lambda d: d["vectors"][126]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "p1d_future_adopt1_tamper",
            lambda d: d["vectors"][126]["expected"].__setitem__("adopted", 1),
        )
        t(
            "p1d_future_ownership_tamper",
            lambda d: d["vectors"][126].__setitem__("ownership", OWNERSHIP_P1A),
        )
        t(
            "p1d_mismatch_future_confuse_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "future_profile_candidate", 1
            ),
        )
        # 127-prefix freeze (includes P1-D; P1-D2 follows at 127).
        t(
            "hundred_twenty_seven_prefix_row_tamper",
            lambda d: d["vectors"][126]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_twenty_seven_prefix_expected_tamper",
            lambda d: d["vectors"][125]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_twenty_seven_prefix_fp_authority_tamper",
            lambda d: d["d3s2_127_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_twenty_seven_prefix_content_authority_tamper",
            lambda d: d["d3s2_127_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-D2 count-green without BIND anti-pass (index 127).
        t(
            "p1d2_probe_delete_tamper",
            lambda d: d["vectors"][127].__setitem__(
                "calls",
                [
                    c
                    for c in d["vectors"][127]["calls"]
                    if c.get("op") != "probe_false_terminal_finalize"
                ],
            ),
        )
        t(
            "p1d2_count_non_green_tamper",
            lambda d: d["vectors"][127]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][127]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][127]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_count_complete_mask": MASK_ATTEMPT,
                },
            ),
        )
        t(
            "p1d2_bind_already_complete_tamper",
            lambda d: d["vectors"][127]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][127]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][127]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_binding_complete_mask": MASK_ATTEMPT | MASK_INDEX,
                },
            ),
        )
        t(
            "p1d2_complete_ready_mid_tamper",
            lambda d: d["vectors"][127]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][127]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][127]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_flags": FLAG_BASELINE_DONE
                    | FLAG_BIND_PHASE_ACTIVE
                    | FLAG_COMPLETE_READY,
                },
            ),
        )
        t(
            "p1d2_phase_not_bind_tamper",
            lambda d: d["vectors"][127]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][127]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][127]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_phase": PHASE_COMPLETE,
                },
            ),
        )
        t(
            "p1d2_probe_status_ok_tamper",
            lambda d: d["vectors"][127]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][127]["calls"])
                    if c.get("op") == "probe_false_terminal_finalize"
                ),
                {
                    "op": "probe_false_terminal_finalize",
                    "expected_status": "OK",
                },
            ),
        )
        t(
            "p1d2_terminal_bind_incomplete_tamper",
            lambda d: d["vectors"][127]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "p1d2_ownership_tamper",
            lambda d: d["vectors"][127].__setitem__("ownership", OWNERSHIP_P1D),
        )
        # 128-prefix freeze (includes P1-D2; P1-B1 follows at 128..129).
        t(
            "hundred_twenty_eight_prefix_row_tamper",
            lambda d: d["vectors"][127]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_twenty_eight_prefix_expected_tamper",
            lambda d: d["vectors"][126]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_twenty_eight_prefix_fp_authority_tamper",
            lambda d: d["d3s2_128_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_twenty_eight_prefix_content_authority_tamper",
            lambda d: d["d3s2_128_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-B1 Mode22 cleanup ordinary-skip (index 128).
        t(
            "p1b1_m22_plan_delete_tamper",
            lambda d: d["vectors"][128].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][128]["rows"]
                    if not (
                        len(bytes.fromhex(r["key_hex"])) >= 10
                        and bytes.fromhex(r["key_hex"])[8] == 6
                        and bytes.fromhex(r["key_hex"])[9] == 0x63
                    )
                ],
            ),
        )
        t(
            "p1b1_m22_skip_disappear_tamper",
            lambda d: d["vectors"][128]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][128]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][128]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_cleanup_skip": 0,
                },
            ),
        )
        t(
            "p1b1_m22_false_corrupt_tamper",
            lambda d: d["vectors"][128]["expected"].__setitem__(
                "final_status", "STORAGE_CORRUPT"
            ),
        )
        t(
            "p1b1_m22_checkpoint_tamper",
            lambda d: d["vectors"][128]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][128]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][128]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_phase": PHASE_FAILED,
                },
            ),
        )
        t(
            "p1b1_m22_ownership_tamper",
            lambda d: d["vectors"][128].__setitem__("ownership", OWNERSHIP_P1D2),
        )
        # P1-B1 Mode23 cleanup still-ordinary (index 129).
        t(
            "p1b1_m23_plan_delete_tamper",
            lambda d: d["vectors"][129].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][129]["rows"]
                    if not (
                        len(bytes.fromhex(r["key_hex"])) >= 10
                        and bytes.fromhex(r["key_hex"])[8] == 6
                        and bytes.fromhex(r["key_hex"])[9] == 0x63
                    )
                ],
            ),
        )
        t(
            "p1b1_m23_false_skip_tamper",
            lambda d: d["vectors"][129]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][129]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][129]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_cleanup_skip": 1,
                },
            ),
        )
        t(
            "p1b1_m23_false_success_tamper",
            lambda d: d["vectors"][129]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1b1_m23_checkpoint_tamper",
            lambda d: d["vectors"][129]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][129]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][129]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_phase": PHASE_COMPLETE,
                },
            ),
        )
        t(
            "p1b1_m23_ownership_tamper",
            lambda d: d["vectors"][129].__setitem__("ownership", OWNERSHIP_P1D2),
        )
        # 130-prefix freeze (includes P1-B1; P1-B2 follows at 130..132).
        t(
            "hundred_thirty_prefix_row_tamper",
            lambda d: d["vectors"][129]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_thirty_prefix_expected_tamper",
            lambda d: d["vectors"][128]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_thirty_prefix_fp_authority_tamper",
            lambda d: d["d3s2_130_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_thirty_prefix_content_authority_tamper",
            lambda d: d["d3s2_130_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-B2 Mode24 cleanup still-ordinary (index 130).
        t(
            "p1b2_m24_plan_delete_tamper",
            lambda d: d["vectors"][130].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][130]["rows"]
                    if not (
                        len(bytes.fromhex(r["key_hex"])) >= 10
                        and bytes.fromhex(r["key_hex"])[8] == 6
                        and bytes.fromhex(r["key_hex"])[9] == 0x63
                    )
                ],
            ),
        )
        t(
            "p1b2_m24_false_skip_tamper",
            lambda d: d["vectors"][130]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][130]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][130]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_cleanup_skip": 1,
                },
            ),
        )
        t(
            "p1b2_m24_false_success_tamper",
            lambda d: d["vectors"][130]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1b2_m24_checkpoint_tamper",
            lambda d: d["vectors"][130]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][130]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][130]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_phase": PHASE_COMPLETE,
                },
            ),
        )
        t(
            "p1b2_m24_ownership_tamper",
            lambda d: d["vectors"][130].__setitem__("ownership", OWNERSHIP_P1B1),
        )
        # P1-B2 Mode25 cleanup still-ordinary (index 131).
        t(
            "p1b2_m25_plan_delete_tamper",
            lambda d: d["vectors"][131].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][131]["rows"]
                    if not (
                        len(bytes.fromhex(r["key_hex"])) >= 10
                        and bytes.fromhex(r["key_hex"])[8] == 6
                        and bytes.fromhex(r["key_hex"])[9] == 0x63
                    )
                ],
            ),
        )
        t(
            "p1b2_m25_false_skip_tamper",
            lambda d: d["vectors"][131]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][131]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][131]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_cleanup_skip": 1,
                },
            ),
        )
        t(
            "p1b2_m25_false_success_tamper",
            lambda d: d["vectors"][131]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1b2_m25_phase_status_tamper",
            lambda d: d["vectors"][131]["expected"].__setitem__(
                "phase", PHASE_COMPLETE
            ),
        )
        t(
            "p1b2_m25_ownership_tamper",
            lambda d: d["vectors"][131].__setitem__("ownership", OWNERSHIP_P1B1),
        )
        # P1-B2 Mode26 cleanup still-ordinary (index 132).
        t(
            "p1b2_m26_plan_delete_tamper",
            lambda d: d["vectors"][132].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][132]["rows"]
                    if not (
                        len(bytes.fromhex(r["key_hex"])) >= 10
                        and bytes.fromhex(r["key_hex"])[8] == 6
                        and bytes.fromhex(r["key_hex"])[9] == 0x63
                    )
                ],
            ),
        )
        t(
            "p1b2_m26_false_skip_tamper",
            lambda d: d["vectors"][132]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][132]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][132]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_cleanup_skip": 1,
                },
            ),
        )
        t(
            "p1b2_m26_false_success_tamper",
            lambda d: d["vectors"][132]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1b2_m26_checkpoint_tamper",
            lambda d: d["vectors"][132]["calls"].__setitem__(
                next(
                    i
                    for i, c in enumerate(d["vectors"][132]["calls"])
                    if int(c.get("has_checkpoint", 0)) == 1
                ),
                {
                    **next(
                        c
                        for c in d["vectors"][132]["calls"]
                        if int(c.get("has_checkpoint", 0)) == 1
                    ),
                    "cp_phase": PHASE_COMPLETE,
                },
            ),
        )
        t(
            "p1b2_m26_ownership_tamper",
            lambda d: d["vectors"][132].__setitem__("ownership", OWNERSHIP_P1B1),
        )
        # 133-prefix freeze (includes P1-B2; P1-C1 follows at 133..135).
        t(
            "hundred_thirty_three_prefix_row_tamper",
            lambda d: d["vectors"][132].__setitem__(
                "rows", list(d["vectors"][132]["rows"])[:-1]
            ),
        )
        t(
            "hundred_thirty_three_prefix_expected_tamper",
            lambda d: d["vectors"][132]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "hundred_thirty_three_prefix_fp_authority_tamper",
            lambda d: d["d3s2_133_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_thirty_three_prefix_content_authority_tamper",
            lambda d: d["d3s2_133_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-C1 Mode23 illegal slot (index 133).
        t(
            "p1c1_illegal_extra_slot_delete_tamper",
            lambda d: d["vectors"][133].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][133]["rows"]
                    if not (
                        len(from_hex(r["key_hex"])) >= 10
                        and from_hex(r["key_hex"])[8] == 6
                        and from_hex(r["key_hex"])[9] == 0x32
                        and _parse_tx_evidence_cell(from_hex(r["value_hex"]))[2]
                        == MODE23_ACCEPTED_L + 1
                    )
                ],
            ),
        )
        t(
            "p1c1_illegal_false_success_tamper",
            lambda d: d["vectors"][133]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c1_illegal_count_mask_clear_tamper",
            lambda d: d["vectors"][133]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "p1c1_illegal_ownership_tamper",
            lambda d: d["vectors"][133].__setitem__("ownership", OWNERSHIP_P1B2),
        )
        # P1-C1 equation fail (index 134).
        t(
            "p1c1_eq_false_success_tamper",
            lambda d: d["vectors"][134]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c1_eq_peer_get_tamper",
            lambda d: d["vectors"][134]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "p1c1_eq_ownership_tamper",
            lambda d: d["vectors"][134].__setitem__("ownership", OWNERSHIP_P1B2),
        )
        # P1-C1 late fail (index 135).
        t(
            "p1c1_late_false_success_tamper",
            lambda d: d["vectors"][135]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c1_late_false_equality_note_tamper",
            lambda d: d["vectors"][135].__setitem__(
                "notes",
                (d["vectors"][135].get("notes") or "")
                + " requires declared_c == observed_c always",
            ),
        )
        t(
            "p1c1_late_ownership_tamper",
            lambda d: d["vectors"][135].__setitem__("ownership", OWNERSHIP_P1B2),
        )
        # P1-C1 cancel slot0 (index 136)
        t(
            "p1c1_cancel_slot0_false_success_tamper",
            lambda d: d["vectors"][136]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c1_cancel_slot0_peer_get_tamper",
            lambda d: d["vectors"][136]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "p1c1_cancel_slot0_ownership_tamper",
            lambda d: d["vectors"][136].__setitem__("ownership", OWNERSHIP_P1B2),
        )
        # multi-owner success (index 137)
        t(
            "p1c1_multi_ok_false_corrupt_tamper",
            lambda d: d["vectors"][137]["expected"].__setitem__(
                "final_status", "STORAGE_CORRUPT"
            ),
        )
        t(
            "p1c1_multi_ok_adopt_clear_tamper",
            lambda d: d["vectors"][137]["expected"].__setitem__("adopted", 0),
        )
        t(
            "p1c1_multi_ok_ownership_tamper",
            lambda d: d["vectors"][137].__setitem__("ownership", OWNERSHIP_P1B2),
        )
        # multi-owner corrupt (index 138)
        t(
            "p1c1_multi_corrupt_false_success_tamper",
            lambda d: d["vectors"][138]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c1_multi_corrupt_peer_get_tamper",
            lambda d: d["vectors"][138]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "p1c1_multi_corrupt_ownership_tamper",
            lambda d: d["vectors"][138].__setitem__("ownership", OWNERSHIP_P1B2),
        )
        # 139-prefix freeze (includes P1-C1; P1-C2 follows at 139..142).
        t(
            "hundred_thirty_nine_prefix_row_tamper",
            lambda d: d["vectors"][138].__setitem__(
                "rows", list(d["vectors"][138]["rows"])[:-1]
            ),
        )
        t(
            "hundred_thirty_nine_prefix_expected_tamper",
            lambda d: d["vectors"][138]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "hundred_thirty_nine_prefix_fp_authority_tamper",
            lambda d: d["d3s2_139_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_thirty_nine_prefix_content_authority_tamper",
            lambda d: d["d3s2_139_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # P1-C2 Mode24 empty secondary undercount (index 139).
        t(
            "p1c2_m24_miss_false_success_tamper",
            lambda d: d["vectors"][139]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c2_m24_miss_peer_get_tamper",
            lambda d: d["vectors"][139]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "p1c2_m24_miss_ownership_tamper",
            lambda d: d["vectors"][139].__setitem__("ownership", OWNERSHIP_P1C1),
        )
        # Mode24 extra disposition (index 140): delete extra RR → model fail.
        t(
            "p1c2_m24_extra_delete_disposition_tamper",
            lambda d: d["vectors"][140].__setitem__(
                "rows",
                [
                    r
                    for r in d["vectors"][140]["rows"]
                    if not (
                        len(from_hex(r["key_hex"])) >= 10
                        and from_hex(r["key_hex"])[8] == 6
                        and from_hex(r["key_hex"])[9] == 0x42
                        and _parse_rr_kind_and_delivery(
                            from_hex(r["value_hex"])
                        )[0]
                        == RR_KIND_DISPOSITION
                    )
                ],
            ),
        )
        t(
            "p1c2_m24_extra_false_success_tamper",
            lambda d: d["vectors"][140]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        # Mode25 missing RECENT (index 141).
        t(
            "p1c2_m25_miss_false_success_tamper",
            lambda d: d["vectors"][141]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c2_m25_miss_obs_a_tamper",
            lambda d: [
                c.__setitem__("cp_observed_a", 1)
                for c in d["vectors"][141]["calls"]
                if int(c.get("has_checkpoint", 0)) == 1
            ],
        )
        # Mode25 extra RECENT (index 142).
        t(
            "p1c2_m25_extra_false_success_tamper",
            lambda d: d["vectors"][142]["expected"].__setitem__(
                "final_status", "OK"
            ),
        )
        t(
            "p1c2_m25_extra_peer_get_tamper",
            lambda d: d["vectors"][142]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "p1c2_m25_extra_ownership_tamper",
            lambda d: d["vectors"][142].__setitem__("ownership", OWNERSHIP_P1C1),
        )
        t(
            "content_sha_tamper",
            lambda d: d.__setitem__("content_sha256", "0" * 64),
        )
        t(
            "d3s1_authority_tamper",
            lambda d: d["d3s1_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )

        # Clean re-check still passes (injected expected/prefix; clean JSON
        # reloaded from disk, expected_doc left untouched by tampers).
        if (
            check(
                clean,
                _expected_doc=expected_doc,
                _prefix_doc=prefix_doc,
            )
            != 0
        ):
            failures.append("self-test: clean re-check failed")

        # Cached authority documents are immutable across all tampers.
        if hashlib.sha256(
            json.dumps(
                expected_doc, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).digest() != expected_doc_canary:
            failures.append("self-test: cached expected_doc mutated")
        if hashlib.sha256(
            json.dumps(
                prefix_doc, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).digest() != prefix_doc_canary:
            failures.append("self-test: cached prefix_doc mutated")

        if failures:
            for f in failures:
                print(f, file=sys.stderr)
            return 1
        print(
            "self-test ok (94+100+102+104+106+108+110+112+113+114+115+119+125+"
            "127+128+130+133+139 prefix freeze + mode25/mode26/mode24/mode23/"
            "mode22/mode21/p0a/p0b/p0c/p0d/p1a/p1d/p1d2/p1b1/p1b2/p1c1(6)/"
            "p1c2(4) slice pins + two-txn anti-pass + forbidden ops + clean pass)"
        )
        return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    """Emit D3-S1 94-array (compat) + separate D3-S2 suffix array/type/count."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    if len(vectors) < D3S1_PREFIX_COUNT:
        raise SystemExit("emit-c-fixture: vector list too short for d3s1 prefix")
    d3s1_vectors = vectors[:D3S1_PREFIX_COUNT]
    d3s2_vectors = vectors[D3S1_PREFIX_COUNT:]
    if len(d3s1_vectors) != D3S1_PREFIX_COUNT:
        raise SystemExit("emit-c-fixture: d3s1 count pin fail")
    if len(d3s2_vectors) != D3S2_SUFFIX_COUNT:
        raise SystemExit(
            f"emit-c-fixture: d3s2 suffix count {len(d3s2_vectors)} != "
            f"{D3S2_SUFFIX_COUNT}"
        )

    lines: List[str] = []
    lines.append(
        "/* Generated by tools/domain_scan_crossrow_d3s2_vector_gen.py — do not edit. */"
    )
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(
        f"#define NINLIL_D3S1_VECTOR_COUNT ((size_t){len(d3s1_vectors)}u)"
    )
    lines.append(
        f"#define NINLIL_D3S2_VECTOR_COUNT ((size_t){len(d3s2_vectors)}u)"
    )
    lines.append(
        f"#define NINLIL_D3S1_WORKSPACE_CEILING_BYTES ((uint32_t){CEILING}u)"
    )
    lines.append("#define NINLIL_D3S1_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_D3S2_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_D3S1_MAX_KEY ((size_t)255u)")
    lines.append("#define NINLIL_D3S1_MAX_VALUE ((size_t)4096u)")
    lines.append("#define NINLIL_D3S1_MAX_ALT ((size_t)4u)")
    lines.append("")
    lines.append("/* No NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN required. */")
    lines.append("")

    # ---- shared binding / row / fault / call shapes (D3-S1 names kept) ----
    lines.append("typedef struct ninlil_d3s1_binding {")
    lines.append("    uint32_t storage_schema;")
    lines.append("    uint32_t role;")
    lines.append("    uint32_t environment;")
    lines.append("    uint8_t runtime_id[16];")
    lines.append("    uint32_t max_services;")
    lines.append("    uint32_t max_nonterminal_transactions;")
    lines.append("    uint32_t max_targets_per_transaction;")
    lines.append("    uint32_t max_logical_payload_bytes;")
    lines.append("    uint64_t max_durable_outbox_payload_bytes;")
    lines.append("    uint32_t max_attempts_per_target_per_cycle;")
    lines.append("    uint32_t max_cancel_attempts_per_transaction;")
    lines.append("    uint32_t max_evidence_per_target;")
    lines.append("    uint32_t max_retained_terminal_transactions;")
    lines.append("    uint32_t max_nonterminal_deliveries;")
    lines.append("    uint32_t max_event_spool_count;")
    lines.append("    uint64_t max_event_spool_bytes;")
    lines.append("    uint32_t max_result_cache_entries;")
    lines.append("    uint32_t max_retained_dispositions;")
    lines.append("    uint32_t max_ingress_per_step;")
    lines.append("    uint32_t max_callbacks_per_step;")
    lines.append("    uint32_t max_state_transitions_per_step;")
    lines.append("    uint32_t max_bearer_sends_per_step;")
    lines.append("    uint32_t max_deferred_tokens;")
    lines.append("    uint64_t terminal_retention_ms;")
    lines.append("    uint64_t result_cache_retention_ms;")
    lines.append("    uint64_t observation_retention_ms;")
    lines.append("} ninlil_d3s1_binding_t;")
    lines.append("")
    lines.append("typedef ninlil_d3s1_binding_t ninlil_d3s2_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_row {")
    lines.append("    uint8_t key[64];")
    lines.append("    uint32_t key_length;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_d3s1_row_t;")
    lines.append("")
    lines.append("typedef ninlil_d3s1_row_t ninlil_d3s2_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    const char *status;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_d3s1_fault_t;")
    lines.append("")
    lines.append("typedef ninlil_d3s1_fault_t ninlil_d3s2_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("    const uint8_t *key;")
    lines.append("    uint32_t key_length;")
    lines.append("    const char *name;")
    lines.append("    uint8_t mode;")
    lines.append("    const char *context; /* NULL, \"null\", or \"alias_session\" */")
    lines.append("    const char *expected_status;")
    lines.append("    /* Call-level production context/spy checkpoint (P0-B). */")
    lines.append("    uint8_t has_checkpoint; /* 0 = no compare; 1 = compare after call */")
    lines.append("    uint8_t cp_phase;")
    lines.append("    uint8_t cp_focus_live;")
    lines.append("    uint64_t cp_observed_a;")
    lines.append("    uint64_t cp_observed_b;")
    lines.append("    uint64_t cp_observed_c;")
    lines.append("    uint8_t cp_count_complete_mask;")
    lines.append("    uint8_t cp_binding_complete_mask;")
    lines.append("    uint8_t cp_flags;")
    lines.append("    uint8_t cp_pass_kind;")
    lines.append("    uint8_t cp_cleanup_skip;")
    lines.append("    uint8_t cp_last_carrier_key_len;")
    lines.append("    const uint8_t *cp_last_carrier_key; /* NULL if len 0 */")
    lines.append("    uint32_t cp_begin_calls;")
    lines.append("    uint32_t cp_iter_open_calls;")
    lines.append("    uint32_t cp_iter_close_calls;")
    lines.append("    uint64_t cp_trace_count;")
    lines.append("} ninlil_d3s1_call_t;")
    lines.append("")
    lines.append("typedef ninlil_d3s1_call_t ninlil_d3s2_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_alt {")
    lines.append("    const char *name;")
    lines.append("    const ninlil_d3s1_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("} ninlil_d3s1_alt_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_expected {")
    lines.append("    const char *final_status;")
    lines.append("    uint32_t adopted;")
    lines.append("    const char *state_after;")
    lines.append("    uint8_t recognizable_future_seen;")
    lines.append("    uint64_t family14_row_count;")
    lines.append("    uint64_t current_domain_key_count;")
    lines.append("    uint64_t ok_row_count;")
    lines.append("    uint8_t profile_exact_active;")
    lines.append("    uint8_t profile_mismatch;")
    lines.append("    uint8_t future_profile_candidate;")
    lines.append("    uint32_t profile_get_present_mask;")
    lines.append("    uint32_t family14_iter_seen_mask;")
    lines.append("    uint32_t reopen_required;")
    lines.append("    uint32_t close_count;")
    lines.append("    uint32_t mutation_calls;")
    lines.append("    uint32_t iter_open_count;")
    lines.append("    const char *const *port_trace;")
    lines.append("    size_t port_trace_count;")
    lines.append("    uint8_t has_sticky_primary;")
    lines.append("    const char *sticky_primary;")
    lines.append("    uint64_t d3_peer_get_count;")
    lines.append("    uint64_t d3_mode_applicable_count;")
    lines.append("} ninlil_d3s1_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s2_expected {")
    lines.append("    const char *final_status;")
    lines.append("    uint32_t adopted;")
    lines.append("    const char *state_after;")
    lines.append("    uint8_t recognizable_future_seen;")
    lines.append("    uint64_t family14_row_count;")
    lines.append("    uint64_t current_domain_key_count;")
    lines.append("    uint64_t ok_row_count;")
    lines.append("    uint8_t profile_exact_active;")
    lines.append("    uint8_t profile_mismatch;")
    lines.append("    uint8_t future_profile_candidate;")
    lines.append("    uint32_t profile_get_present_mask;")
    lines.append("    uint32_t family14_iter_seen_mask;")
    lines.append("    uint32_t reopen_required;")
    lines.append("    uint32_t close_count;")
    lines.append("    uint32_t mutation_calls;")
    lines.append("    uint32_t iter_open_count;")
    lines.append("    const char *const *port_trace;")
    lines.append("    size_t port_trace_count;")
    lines.append("    uint8_t has_sticky_primary;")
    lines.append("    const char *sticky_primary;")
    lines.append("    uint64_t d3_peer_get_count;")
    lines.append("    uint64_t d3_mode_applicable_count;")
    lines.append("    uint8_t phase;")
    lines.append("    uint8_t count_complete_mask;")
    lines.append("    uint8_t binding_complete_mask;")
    lines.append("    uint8_t flags;")
    # note_count is formal JSON/oracle only (generator check/self-test).
    # Not emitted to the production bridge C fixture: no note_terminal_corrupt
    # call-count seam exists without session/context ABI growth.
    lines.append("} ninlil_d3s2_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    uint8_t mode;")
    lines.append("    ninlil_d3s1_binding_t candidate;")
    lines.append("    const ninlil_d3s1_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_d3s1_alt_t *alts;")
    lines.append("    size_t alt_count;")
    lines.append("    const ninlil_d3s1_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_d3s1_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_d3s1_expected_t expected;")
    lines.append("} ninlil_d3s1_vector_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s2_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    uint8_t mode;")
    lines.append("    ninlil_d3s2_binding_t candidate;")
    lines.append("    const ninlil_d3s2_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_d3s2_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_d3s2_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_d3s2_expected_t expected;")
    lines.append("} ninlil_d3s2_vector_t;")
    lines.append("")

    def c_bytes_literal(data_b: bytes, name: str) -> List[str]:
        out = [f"static const uint8_t {name}[] = {{"]
        if data_b:
            parts = [f"0x{b:02x}" for b in data_b]
            for i in range(0, len(parts), 12):
                out.append("    " + ", ".join(parts[i : i + 12]) + ",")
        else:
            out.append("    0x00,")
        out.append("};")
        return out

    def binding_literal(fields: Dict[str, Any]) -> str:
        rid = from_hex(fields["runtime_id_hex"])
        rid_l = ", ".join(f"0x{b:02x}" for b in rid)
        lim = fields["limits"]
        return (
            "{ "
            f"{int(fields['storage_schema'])}u, {int(fields['role'])}u, "
            f"{int(fields['environment'])}u, {{ {rid_l} }}, "
            f"{int(lim['max_services'])}u, "
            f"{int(lim['max_nonterminal_transactions'])}u, "
            f"{int(lim['max_targets_per_transaction'])}u, "
            f"{int(lim['max_logical_payload_bytes'])}u, "
            f"{int(lim['max_durable_outbox_payload_bytes'])}ull, "
            f"{int(lim['max_attempts_per_target_per_cycle'])}u, "
            f"{int(lim['max_cancel_attempts_per_transaction'])}u, "
            f"{int(lim['max_evidence_per_target'])}u, "
            f"{int(lim['max_retained_terminal_transactions'])}u, "
            f"{int(lim['max_nonterminal_deliveries'])}u, "
            f"{int(lim['max_event_spool_count'])}u, "
            f"{int(lim['max_event_spool_bytes'])}ull, "
            f"{int(lim['max_result_cache_entries'])}u, "
            f"{int(lim['max_retained_dispositions'])}u, "
            f"{int(lim['max_ingress_per_step'])}u, "
            f"{int(lim['max_callbacks_per_step'])}u, "
            f"{int(lim['max_state_transitions_per_step'])}u, "
            f"{int(lim['max_bearer_sends_per_step'])}u, "
            f"{int(lim['max_deferred_tokens'])}u, "
            f"{int(fields['terminal_retention_ms'])}ull, "
            f"{int(fields['result_cache_retention_ms'])}ull, "
            f"{int(fields['observation_retention_ms'])}ull "
            "}"
        )

    # ---- D3-S1 94 (compat) ----
    for vi, vec in enumerate(d3s1_vectors):
        for ri, row in enumerate(vec.get("rows", [])):
            val = from_hex(row["value_hex"])
            lines.extend(c_bytes_literal(val, f"ninlil_d3s1_{vi}_v{ri}"))
        lines.append(f"static const ninlil_d3s1_row_t ninlil_d3s1_{vi}_rows[] = {{")
        for ri, row in enumerate(vec.get("rows", [])):
            key = from_hex(row["key_hex"])
            key_l = ", ".join(f"0x{b:02x}" for b in key)
            pad = ", ".join("0x00" for _ in range(max(0, 64 - len(key))))
            key_arr = key_l + ((", " + pad) if pad else "")
            lines.append(
                f"    {{ {{ {key_arr} }}, {len(key)}u, "
                f"ninlil_d3s1_{vi}_v{ri}, {len(from_hex(row['value_hex']))}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { {0}, 0u, NULL, 0u },")
        lines.append("};")
        lines.append(f"static const ninlil_d3s1_alt_t ninlil_d3s1_alts_{vi}[] = {{")
        lines.append("    { NULL, NULL, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s1_fault_t ninlil_d3s1_faults_{vi}[] = {{"
        )
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f.get("op", "")}", {int(f.get("on_call", 0))}u, '
                f'"{f.get("shape", "natural")}", "{f.get("status", "OK")}", '
                f'{int(f.get("key_length", 0))}u, '
                f'{int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { "", 0u, "", "", 0u, 0u },')
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s1_call_t ninlil_d3s1_calls_{vi}[] = {{"
        )
        for ci, c in enumerate(vec["calls"]):
            mode_c = int(c.get("mode", vec.get("mode", 0)))
            ctx = c.get("context")
            ctx_s = f'"{ctx}"' if ctx else "NULL"
            has_cp = int(c.get("has_checkpoint", 0))
            lines.append(
                f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u, NULL, 0u, '
                f'"{c.get("name", "")}", {mode_c}u, {ctx_s}, '
                f'"{c.get("expected_status", "")}", '
                f'{has_cp}u, '
                f'{int(c.get("cp_phase", 0))}u, '
                f'{int(c.get("cp_focus_live", 0))}u, '
                f'{int(c.get("cp_observed_a", 0))}ull, '
                f'{int(c.get("cp_observed_b", 0))}ull, '
                f'{int(c.get("cp_observed_c", 0))}ull, '
                f'0x{int(c.get("cp_count_complete_mask", 0)):02x}u, '
                f'0x{int(c.get("cp_binding_complete_mask", 0)):02x}u, '
                f'0x{int(c.get("cp_flags", 0)):02x}u, '
                f'{int(c.get("cp_pass_kind", 0))}u, '
                f'{int(c.get("cp_cleanup_skip", 0))}u, '
                f'{int(c.get("cp_last_carrier_key_len", 0))}u, '
                f'NULL, '
                f'{int(c.get("cp_begin_calls", 0))}u, '
                f'{int(c.get("cp_iter_open_calls", 0))}u, '
                f'{int(c.get("cp_iter_close_calls", 0))}u, '
                f'{int(c.get("cp_trace_count", 0))}ull }},'
            )
        lines.append("};")
        exp = vec["expected"]
        lines.append(f"static const char *const ninlil_d3s1_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append('    "",')
        lines.append("};")

    lines.append(
        "static const ninlil_d3s1_vector_t "
        "ninlil_d3s1_vectors[NINLIL_D3S1_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(d3s1_vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {int(vec.get('mode', 0))}u,")
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_d3s1_{vi}_rows, {len(vec.get('rows', []))}u,"
        )
        lines.append(f"        ninlil_d3s1_alts_{vi}, 0u,")
        lines.append(
            f"        ninlil_d3s1_faults_{vi}, {len(vec.get('faults', []))}u,"
        )
        lines.append(f"        ninlil_d3s1_calls_{vi}, {len(vec['calls'])}u,")
        lines.append("        {")
        lines.append(f'            "{exp["final_status"]}",')
        lines.append(f"            {int(exp['adopted'])}u,")
        lines.append(f'            "{exp["state_after"]}",')
        lines.append(f"            {int(exp['recognizable_future_seen'])}u,")
        lines.append(f"            {int(exp['family14_row_count'])}ull,")
        lines.append(f"            {int(exp['current_domain_key_count'])}ull,")
        lines.append(f"            {int(exp['ok_row_count'])}ull,")
        lines.append(f"            {int(exp['profile_exact_active'])}u,")
        lines.append(f"            {int(exp['profile_mismatch'])}u,")
        lines.append(f"            {int(exp['future_profile_candidate'])}u,")
        lines.append(f"            0x{int(exp['profile_get_present_mask']):x}u,")
        lines.append(f"            0x{int(exp['family14_iter_seen_mask']):x}u,")
        lines.append(f"            {int(exp['reopen_required'])}u,")
        lines.append(f"            {int(exp.get('close_count', 0))}u,")
        lines.append(f"            {int(exp['mutation_calls'])}u,")
        lines.append(f"            {int(exp['iter_open_count'])}u,")
        lines.append(
            f"            ninlil_d3s1_trace_{vi}, "
            f"{len(exp.get('port_trace', []))}u,"
        )
        lines.append(f"            {int(exp['has_sticky_primary'])}u,")
        lines.append(f'            "{exp.get("sticky_primary", "")}",')
        lines.append(f"            {int(exp.get('d3_peer_get_count', 0))}ull,")
        lines.append(
            f"            {int(exp.get('d3_mode_applicable_count', 0))}ull"
        )
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")

    # ---- D3-S2 suffix (smoke + Mode25 + Mode26 + Mode24) ----
    for vi, vec in enumerate(d3s2_vectors):
        for ri, row in enumerate(vec.get("rows", [])):
            val = from_hex(row["value_hex"])
            lines.extend(c_bytes_literal(val, f"ninlil_d3s2_{vi}_v{ri}"))
        lines.append(f"static const ninlil_d3s2_row_t ninlil_d3s2_{vi}_rows[] = {{")
        for ri, row in enumerate(vec.get("rows", [])):
            key = from_hex(row["key_hex"])
            key_l = ", ".join(f"0x{b:02x}" for b in key)
            pad = ", ".join("0x00" for _ in range(max(0, 64 - len(key))))
            key_arr = key_l + ((", " + pad) if pad else "")
            lines.append(
                f"    {{ {{ {key_arr} }}, {len(key)}u, "
                f"ninlil_d3s2_{vi}_v{ri}, {len(from_hex(row['value_hex']))}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { {0}, 0u, NULL, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s2_fault_t ninlil_d3s2_faults_{vi}[] = {{"
        )
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f.get("op", "")}", {int(f.get("on_call", 0))}u, '
                f'"{f.get("shape", "natural")}", "{f.get("status", "OK")}", '
                f'{int(f.get("key_length", 0))}u, '
                f'{int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { "", 0u, "", "", 0u, 0u },')
        lines.append("};")
        # Optional last_carrier_key bytes for checkpoint calls.
        for ci, c in enumerate(vec["calls"]):
            if int(c.get("has_checkpoint", 0)) == 1 and c.get(
                "cp_last_carrier_key_hex"
            ):
                kb = from_hex(c["cp_last_carrier_key_hex"])
                lines.extend(
                    c_bytes_literal(kb, f"ninlil_d3s2_{vi}_cpkey_{ci}")
                )
        lines.append(
            f"static const ninlil_d3s2_call_t ninlil_d3s2_calls_{vi}[] = {{"
        )
        for ci, c in enumerate(vec["calls"]):
            mode_c = int(c.get("mode", vec.get("mode", 0)))
            ctx = c.get("context")
            ctx_s = f'"{ctx}"' if ctx else "NULL"
            has_cp = int(c.get("has_checkpoint", 0))
            if has_cp == 1 and c.get("cp_last_carrier_key_hex"):
                key_ptr = f"ninlil_d3s2_{vi}_cpkey_{ci}"
            else:
                key_ptr = "NULL"
            lines.append(
                f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u, NULL, 0u, '
                f'"{c.get("name", "")}", {mode_c}u, {ctx_s}, '
                f'"{c.get("expected_status", "")}", '
                f'{has_cp}u, '
                f'{int(c.get("cp_phase", 0))}u, '
                f'{int(c.get("cp_focus_live", 0))}u, '
                f'{int(c.get("cp_observed_a", 0))}ull, '
                f'{int(c.get("cp_observed_b", 0))}ull, '
                f'{int(c.get("cp_observed_c", 0))}ull, '
                f'0x{int(c.get("cp_count_complete_mask", 0)):02x}u, '
                f'0x{int(c.get("cp_binding_complete_mask", 0)):02x}u, '
                f'0x{int(c.get("cp_flags", 0)):02x}u, '
                f'{int(c.get("cp_pass_kind", 0))}u, '
                f'{int(c.get("cp_cleanup_skip", 0))}u, '
                f'{int(c.get("cp_last_carrier_key_len", 0))}u, '
                f'{key_ptr}, '
                f'{int(c.get("cp_begin_calls", 0))}u, '
                f'{int(c.get("cp_iter_open_calls", 0))}u, '
                f'{int(c.get("cp_iter_close_calls", 0))}u, '
                f'{int(c.get("cp_trace_count", 0))}ull }},'
            )
        lines.append("};")
        exp = vec["expected"]
        lines.append(f"static const char *const ninlil_d3s2_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append('    "",')
        lines.append("};")

    lines.append(
        "static const ninlil_d3s2_vector_t "
        "ninlil_d3s2_vectors[NINLIL_D3S2_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(d3s2_vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {int(vec.get('mode', 0))}u,")
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_d3s2_{vi}_rows, {len(vec.get('rows', []))}u,"
        )
        lines.append(
            f"        ninlil_d3s2_faults_{vi}, {len(vec.get('faults', []))}u,"
        )
        lines.append(f"        ninlil_d3s2_calls_{vi}, {len(vec['calls'])}u,")
        lines.append("        {")
        lines.append(f'            "{exp["final_status"]}",')
        lines.append(f"            {int(exp['adopted'])}u,")
        lines.append(f'            "{exp["state_after"]}",')
        lines.append(f"            {int(exp['recognizable_future_seen'])}u,")
        lines.append(f"            {int(exp['family14_row_count'])}ull,")
        lines.append(f"            {int(exp['current_domain_key_count'])}ull,")
        lines.append(f"            {int(exp['ok_row_count'])}ull,")
        lines.append(f"            {int(exp['profile_exact_active'])}u,")
        lines.append(f"            {int(exp['profile_mismatch'])}u,")
        lines.append(f"            {int(exp['future_profile_candidate'])}u,")
        lines.append(f"            0x{int(exp['profile_get_present_mask']):x}u,")
        lines.append(f"            0x{int(exp['family14_iter_seen_mask']):x}u,")
        lines.append(f"            {int(exp['reopen_required'])}u,")
        lines.append(f"            {int(exp.get('close_count', 0))}u,")
        lines.append(f"            {int(exp['mutation_calls'])}u,")
        lines.append(f"            {int(exp['iter_open_count'])}u,")
        lines.append(
            f"            ninlil_d3s2_trace_{vi}, "
            f"{len(exp.get('port_trace', []))}u,"
        )
        lines.append(f"            {int(exp['has_sticky_primary'])}u,")
        lines.append(f'            "{exp.get("sticky_primary", "")}",')
        lines.append(f"            {int(exp.get('d3_peer_get_count', 0))}ull,")
        lines.append(
            f"            {int(exp.get('d3_mode_applicable_count', 0))}ull,"
        )
        lines.append(f"            {int(exp['phase'])}u,")
        lines.append(f"            0x{int(exp['count_complete_mask']):02x}u,")
        lines.append(f"            0x{int(exp['binding_complete_mask']):02x}u,")
        lines.append(f"            0x{int(exp['flags']):02x}u")
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H */")
    lines.append("")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    # Temp + atomic replace so a concurrent reader never sees a partial header
    # if a generator rule is ever double-scheduled (defense in depth; CMake
    # custom_target ownership is the primary race stop).
    payload = "\n".join(lines)
    fd, tmp_name = tempfile.mkstemp(
        prefix=header_path.name + ".",
        suffix=".tmp",
        dir=str(header_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
            tmp_f.write(payload)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        os.replace(tmp_name, header_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    print(
        f"wrote {header_path} "
        f"(d3s1={len(d3s1_vectors)} d3s2={len(d3s2_vectors)} vectors)"
    )


# ---------------------------------------------------------------------------
# P0-D Mode22 INDEX/ABSENT + PVD + pair subject residual (§18.13.15 #8/#15)
# True-primary raw after D1 PRESENT is unconstructible — not covered here.
# ---------------------------------------------------------------------------


def _domain_subtype(row: Dict[str, str]) -> Optional[int]:
    k = from_hex(row["key_hex"])
    if len(k) >= 10 and k[8] == 6:
        return int(k[9])
    return None


def _mode22_add_unexpected_aii(
    rows: List[Dict[str, str]], named: Dict[str, Dict[str, str]], dlv_pvd: bytes
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]]]:
    """Append D1 ATTEMPT_ID_INDEX (same attempt_id) for Mode22 PRESENT fail.

    Mode22 BIND_ATTEMPT only requires INDEX ABSENT at the pair peer key.
    D1 AII is TX-form record_kd (not DLV ATTEMPT complete-key); that is
    fine — presence alone is the Mode22 corrupt finding.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    aii = cat[D1_AII_ID]
    att_okind, _oraw, att_id, att_txn, _kind, _pkd, _pvd = _parse_attempt_dlv(
        from_hex(named["att"]["value_hex"])
    )
    if att_okind != ATT_OWNER_KIND_DELIVERY:
        raise SystemExit("unexpected AII material requires DELIVERY ATT")
    aii_key = from_hex(aii["key_hex"])
    aii_val = _d3s1.patch_pvd(from_hex(aii["value_hex"]), dlv_pvd)
    aii_id, aii_txn, _aii_kind, _rkd, aii_pvd = _parse_attempt_id_index(aii_val)
    if aii_id != att_id or aii_txn != att_txn:
        raise SystemExit("D1 AII attempt_id/txn must match DLV ATT for pair key")
    if aii_pvd != dlv_pvd:
        raise SystemExit("unexpected AII PVD must equal DELIVERY VALUE_DIGEST")
    if _d3s1.domain_value_framing(aii_val) != "current":
        raise SystemExit("unexpected AII envelope framing not current")
    named = dict(named)
    named["aii"] = {
        "key_hex": hex_of(aii_key),
        "value_hex": hex_of(aii_val),
    }
    out = list(rows) + [named["aii"]]
    out = sorted(out, key=lambda r: from_hex(r["key_hex"]))
    return out, named


def run_d3s2_mode22_att_unexpected_aii_index_present_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22: RC+DLV+ATT with unexpected ATTEMPT_ID_INDEX PRESENT.

    Carrier RC + true DELIVERY proven, then pair peer INDEX PRESENT →
    note_terminal_corrupt STORAGE_CORRUPT. BIND incomplete; mutation 0.
    """
    n_ok = len(rows)
    if n_ok != 21:
        raise SystemExit(
            f"mode22 unexpected INDEX expects 21 rows (17+4), got {n_ok}"
        )
    aii_n = sum(1 for r in rows if _domain_subtype(r) == 0x34)
    if aii_n != 1:
        raise SystemExit(
            f"mode22 unexpected INDEX must ship exact 1 AII, got {aii_n}"
        )
    n_drive = 5
    n_open = 5
    walk = _walk_trace_segment(n_ok)

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"}
    ]
    for i in range(n_drive):
        if i + 1 == n_drive:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
        else:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT: profile + ATT + AII + DLV + RC install + setup gets
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("iter_next")  # AII residual
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE carrier
    port_trace.append("get")  # CANCEL_STATE ABSENT
    port_trace.append("get")  # CLEANUP_PLAN ABSENT
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_ATTEMPT: RC + DELIVERY then INDEX PRESENT → note stop
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ATTEMPT secondary
    port_trace.append("get")  # carrier RESULT_CACHE
    port_trace.append("get")  # true primary DELIVERY
    port_trace.append("get")  # pair peer ATTEMPT_ID_INDEX PRESENT → note
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 4,  # ATT + AII + DLV + RC
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # SELECT setup 2 + BIND 3 (carrier + primary + INDEX PRESENT)
        "d3_peer_get_count": 5,
        "d3_mode_applicable_count": 1,
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_ATTEMPT,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


def run_d3s2_mode22_att_true_primary_delivery_absent_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22: RC+ATT without DELIVERY → BIND true-primary ABSENT note.

    Carrier companion RESULT_CACHE is proven first; primary DELIVERY
    exact_get ABSENT → note_terminal_corrupt. INDEX probe must not run.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode22 primary-absent expects 19 rows (17+2: ATT+RC), got {n_ok}"
        )
    if any(_domain_subtype(r) == 0x40 for r in rows):
        raise SystemExit("mode22 primary-absent must not ship DELIVERY")
    if sum(1 for r in rows if _domain_subtype(r) == 0x41) != 1:
        raise SystemExit("mode22 primary-absent must ship exact 1 RESULT_CACHE")
    n_drive = 5
    n_open = 5
    walk = _walk_trace_segment(n_ok)

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"}
    ]
    for i in range(n_drive):
        if i + 1 == n_drive:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
        else:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT: profile + ATT + RC (no DLV)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("iter_next")  # RESULT_CACHE carrier
    port_trace.append("get")  # CANCEL_STATE
    port_trace.append("get")  # CLEANUP_PLAN
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # BIND: ATT → RC OK → DELIVERY ABSENT note (INDEX not probed)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("get")  # carrier RESULT_CACHE
    port_trace.append("get")  # true primary DELIVERY → ABSENT
    port_trace.append("iter_close")
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ATT + RC
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # SELECT setup 2 + BIND carrier + primary ABSENT
        "d3_peer_get_count": 4,
        "d3_mode_applicable_count": 1,
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_ATTEMPT,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


def run_d3s2_mode21_att_primary_pvd_mismatch_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21: ANCHOR+STATE+ATT+AII with ATT header PVD ≠ live ANCHOR digest.

    Carrier STATE proven; true-primary PRESENT; VALUE_DIGEST mismatch →
    note_terminal_corrupt. Pair probe must not run. Unit promotion of
    test_d3s2_p1_mode21_bind_primary_pvd_mismatch.
    """
    n_ok = len(rows)
    if n_ok != 21:
        raise SystemExit(
            f"mode21 pvd-mismatch expects 21 rows (17+4), got {n_ok}"
        )
    n_drive = 6
    n_open = 6
    walk = _walk_trace_segment(n_ok)

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 21, "expected_status": "OK"}
    ]
    for i in range(n_drive):
        if i + 1 == n_drive:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
        else:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT carrier
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("get")  # CANCEL
    port_trace.append("get")  # CLEANUP
    port_trace.append("iter_next")  # ATT
    port_trace.append("iter_next")  # AII
    port_trace.append("iter_next")  # NF
    port_trace.append("iter_close")
    # FOCUS_ATTEMPT
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # FOCUS_INDEX
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT empty → BIND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # BIND_ATTEMPT: STATE + ANCHOR PVD fail (pair not reached)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATT
    port_trace.append("get")  # carrier STATE
    port_trace.append("get")  # true primary ANCHOR → PVD mismatch note
    port_trace.append("iter_close")
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 4,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # SELECT setup 2 + BIND carrier + primary PVD fail
        "d3_peer_get_count": 4,
        "d3_mode_applicable_count": 1,
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


def run_d3s2_mode21_att_index_pair_subject_raw_mismatch_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21: INDEX PRESENT at pair key but body txn/subject mismatches ATT.

    CLEANUP_PLAN PRESENT so wrong-txn AII does not undercount FOCUS_INDEX.
    BIND_ATTEMPT proves STATE carrier + ANCHOR primary, then pair body
    subject mismatch → note. This is pair ATTEMPT_ID_INDEX subject/raw
    mismatch only — not true-primary raw mismatch. True-primary raw after
    D1 PRESENT+typed validate is identity-tautological/unconstructible
    under same-record + same READ_ONLY snapshot (case 8 residual closed
    only for constructible pair subject; primary raw left unclaimed).
    """
    n_ok = len(rows)
    if n_ok != 22:
        raise SystemExit(
            f"mode21 pair-subject expects 22 rows (17+5: ANCHOR+STATE+ATT+"
            f"AII+CP), got {n_ok}"
        )
    n_drive = 6
    n_open = 6
    walk = _walk_trace_segment(n_ok)

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 21, "expected_status": "OK"}
    ]
    for i in range(n_drive):
        if i + 1 == n_drive:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
        else:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})

    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT: ANCHOR STATE ATT AII CP; CLEANUP PRESENT → cleanup_skip
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("get")  # CANCEL
    port_trace.append("get")  # CLEANUP PRESENT
    port_trace.append("iter_next")  # ATT
    port_trace.append("iter_next")  # AII (wrong txn; stream may skip)
    port_trace.append("iter_next")  # CP
    port_trace.append("iter_next")  # NF
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # BIND_ATTEMPT: STATE + ANCHOR + INDEX PRESENT body subject fail
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATT
    port_trace.append("get")  # carrier STATE
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("get")  # pair INDEX PRESENT subject/raw fail
    port_trace.append("iter_close")
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 5,  # ANCHOR+STATE+ATT+AII+CP
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        # SELECT setup 2 + BIND 3 (carrier + primary + pair subject fail)
        "d3_peer_get_count": 5,
        "d3_mode_applicable_count": 1,
        "phase": PHASE_FAILED,
        "count_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


def _rekey_aii_wrong_txn_for_pair_subject(
    aii_value: bytes, *, att_id: bytes, att_txn: bytes, anchor_pvd: bytes
) -> bytes:
    """D1-valid AII at same attempt_id key with flipped transaction_id.

    record_kd recomputed for TX-form (wrong_txn || aid). PVD → ANCHOR.
    """
    st, body, _ = _d3s1.extract_envelope(aii_value)
    if st != 0x34 or len(body) != AII_BODY_LEN:
        raise SystemExit("AII rekey: not typed ATTEMPT_ID_INDEX body 100")
    if bytes(body[0:16]) != att_id:
        raise SystemExit("AII rekey: attempt_id must match ATT for pair key")
    wrong_txn = bytearray(att_txn)
    wrong_txn[-1] = wrong_txn[-1] ^ 0x01
    wrong_txn_b = bytes(wrong_txn)
    if wrong_txn_b == att_txn:
        raise SystemExit("AII rekey: txn flip produced identity")
    kind = struct.unpack_from(">H", body, 32)[0]
    rkd = _d3s1.key_digest(
        _attempt_composite_key(ATT_OWNER_KIND_TRANSACTION, wrong_txn_b, att_id)
    )
    b = bytearray(body)
    b[0:16] = att_id
    b[16:32] = wrong_txn_b
    struct.pack_into(">H", b, 32, int(kind))
    struct.pack_into(">H", b, 34, 0)
    b[AII_ATTEMPT_RECORD_KEY_DIGEST_OFF : AII_ATTEMPT_RECORD_KEY_DIGEST_OFF + 32] = (
        rkd
    )
    out = bytearray(aii_value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("AII body not found in envelope")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[24:40] = wrong_txn_b  # primary_id
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    val = _d3s1.patch_pvd(bytes(out), anchor_pvd)
    aii_id, aii_txn, _k, aii_rkd, aii_pvd = _parse_attempt_id_index(val)
    if aii_id != att_id or aii_txn != wrong_txn_b:
        raise SystemExit("AII rekey identity did not stick")
    if aii_rkd != rkd or aii_pvd != anchor_pvd:
        raise SystemExit("AII rekey digest/PVD did not stick")
    if _d3s1.domain_value_framing(val) != "current":
        raise SystemExit("AII rekey framing not current")
    return val


def build_d3s2_p0d_slice_vectors() -> List[Dict[str, Any]]:
    """P0-D append-only slice (4 vectors) after the frozen 115-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # 1) Mode22 unexpected ATTEMPT_ID_INDEX PRESENT
    rows1, named1, pvd1 = _mode22_material_rows(include_rc=True)
    rows1, named1 = _mode22_add_unexpected_aii(rows1, named1, pvd1)
    calls1, exp1 = run_d3s2_mode22_att_unexpected_aii_index_present_corrupt(
        binding, rows1
    )
    vectors.append(
        {
            "id": "D3S2_M22_ATT_UNEXPECTED_AII_INDEX_PRESENT",
            "kind": "mode22_att_unexpected_aii_index_present_corrupt",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows1),
            "alt_rows": {},
            "faults": [],
            "calls": calls1,
            "d1_refs": [D1_RC_ID, D1_ATT_DLV_ID, D1_DLV_ID, D1_AII_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_DLV_ID,
                row=named1["att"],
                expect_presence="PRESENT",
                note=(
                    "DELIVERY-owned COMMAND ATTEMPT; Mode22 INDEX expect 0 via "
                    "BIND_ATTEMPT ABSENT peer only"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_AII_ID,
                row=named1["aii"],
                expect_presence="PRESENT",
                note=(
                    "unexpected ATTEMPT_ID_INDEX PRESENT at pair peer key "
                    "(Mode22 ABSENT-peer fail)"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_RC_ID,
                    row=named1["rc"],
                    expect_presence="PRESENT",
                    note="carrier RESULT_CACHE proven before INDEX pair",
                ),
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named1["delivery"],
                    expect_presence="PRESENT",
                    note="true primary DELIVERY proven before INDEX pair",
                ),
            ],
            "notes": (
                "P0-D formal (§18.13.15 cases 8/15): Mode22 DELIVERY-owned "
                "ATTEMPT with live RESULT_CACHE app=1 and true DELIVERY; "
                "ATTEMPT_ID_INDEX is PRESENT though Mode22 INDEX expect 0 "
                "and has no FOCUS_INDEX/BIND_INDEX. BIND_ATTEMPT proves "
                "carrier RC subject + DELIVERY PVD/raw then pair peer "
                "INDEX PRESENT → note_terminal_corrupt STORAGE_CORRUPT. "
                "Single READ_ONLY txn; abort; mutation_calls=0; binding "
                "mask incomplete. Independent Python only."
            ),
            "ownership": OWNERSHIP_P0D,
            "expected": exp1,
        }
    )

    # 2) Mode22 true-primary DELIVERY ABSENT (carrier RC present)
    rows2, named2, _pvd2 = _mode22_material_rows(include_rc=True)
    rows2 = [r for r in rows2 if _domain_subtype(r) != 0x40]
    if "delivery" in named2:
        del named2["delivery"]
    calls2, exp2 = run_d3s2_mode22_att_true_primary_delivery_absent_corrupt(
        binding, rows2
    )
    vectors.append(
        {
            "id": "D3S2_M22_ATT_TRUE_PRIMARY_DELIVERY_ABSENT",
            "kind": "mode22_att_true_primary_delivery_absent_corrupt",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows2),
            "alt_rows": {},
            "faults": [],
            "calls": calls2,
            "d1_refs": [D1_RC_ID, D1_ATT_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_DLV_ID,
                row=named2["att"],
                expect_presence="PRESENT",
                note="DELIVERY-owned ATTEMPT secondary; true primary missing",
            ),
            "peer_ref": _d3s1.none_ref(
                "true primary DELIVERY exact_get ABSENT after carrier RC proven "
                "(INDEX probe must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_RC_ID,
                    row=named2["rc"],
                    expect_presence="PRESENT",
                    note="carrier RESULT_CACHE present and subject-matched first",
                )
            ],
            "notes": (
                "P0-D formal (§18.13.15 case 8): Mode22 true-primary ABSENT — "
                "RESULT_CACHE carrier PRESENT (app=1) and DELIVERY-owned "
                "ATTEMPT PRESENT, but DELIVERY primary row is missing. "
                "BIND_ATTEMPT proves carrier then notes true-primary ABSENT "
                "via note_terminal_corrupt. Pair INDEX ABSENT probe must not "
                "run. abort; mutation_calls=0. Independent of production C."
            ),
            "ownership": OWNERSHIP_P0D,
            "expected": exp2,
        }
    )

    # 3) Mode21 primary PVD mismatch (unit promotion)
    rows3, named3, anchor_pvd3 = _mode21_material_rows(
        include_aii=True, include_cleanup_plan=False
    )
    cat = _d1_catalog()
    # Replace ATT with unpatched D1 value (placeholder PVD ≠ live ANCHOR).
    att_key = from_hex(named3["att"]["key_hex"])
    att_unpatched = from_hex(cat[D1_ATT_TX_ID]["value_hex"])
    if _d3s1.extract_envelope(att_unpatched)[2] == anchor_pvd3:
        raise SystemExit("mode21 pvd-mismatch requires unpatched PVD != ANCHOR")
    named3["att"] = {
        "key_hex": hex_of(att_key),
        "value_hex": hex_of(att_unpatched),
    }
    rows3 = []
    for r in _mode21_material_rows(include_aii=True, include_cleanup_plan=False)[0]:
        if _domain_subtype(r) == 0x31:
            rows3.append(named3["att"])
        else:
            rows3.append(r)
    rows3 = sorted(rows3, key=lambda r: from_hex(r["key_hex"]))
    # Re-fetch named anchor/state/aii from rebuilt rows
    named3_full = dict(named3)
    for r in rows3:
        st = _domain_subtype(r)
        if st == 0x20:
            named3_full["anchor"] = r
        elif st == 0x22:
            named3_full["state"] = r
        elif st == 0x34:
            named3_full["aii"] = r
    calls3, exp3 = run_d3s2_mode21_att_primary_pvd_mismatch_corrupt(
        binding, rows3
    )
    vectors.append(
        {
            "id": "D3S2_M21_ATT_PRIMARY_PVD_MISMATCH",
            "kind": "mode21_att_primary_pvd_mismatch_corrupt",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows3),
            "alt_rows": {},
            "faults": [],
            "calls": calls3,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_ID, D1_AII_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_TX_ID,
                row=named3_full["att"],
                expect_presence="PRESENT",
                note=(
                    "TX ATTEMPT with unpatched header PVD (≠ live ANCHOR "
                    "VALUE_DIGEST); unit-test promotion"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named3_full["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR PRESENT; PVD mismatch is the fail",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_STATE_ID,
                    row=named3_full["state"],
                    expect_presence="PRESENT",
                    note="carrier STATE proven before primary PVD fail",
                ),
                _d3s1.d1_ref_from_id(
                    D1_AII_ID,
                    row=named3_full["aii"],
                    expect_presence="PRESENT",
                    note="AII present for FOCUS count; BIND_INDEX must not run",
                ),
            ],
            "notes": (
                "P0-D formal (§18.13.15 case 8): Mode21 primary PVD mismatch — "
                "STATE+ANCHOR+ATT+AII live; ATT header primary_value_digest "
                "is the D1 placeholder (not patched to live ANCHOR "
                "VALUE_DIGEST). BIND_ATTEMPT proves STATE carrier then notes "
                "true-primary PVD mismatch. Pair INDEX get must not run. "
                "Promotes unit test_d3s2_p1_mode21_bind_primary_pvd_mismatch. "
                "abort; mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P0D,
            "expected": exp3,
        }
    )

    # 4) Mode21 INDEX pair PRESENT subject mismatch (not true-primary raw)
    rows4, named4, anchor_pvd4 = _mode21_material_rows(
        include_aii=True, include_cleanup_plan=True
    )
    (
        _okind,
        _oraw,
        att_id4,
        att_txn4,
        _akind,
        _pkd,
        _apvd,
    ) = _parse_attempt_tx(from_hex(named4["att"]["value_hex"]))
    aii_bad = _rekey_aii_wrong_txn_for_pair_subject(
        from_hex(named4["aii"]["value_hex"]),
        att_id=att_id4,
        att_txn=att_txn4,
        anchor_pvd=anchor_pvd4,
    )
    named4["aii"] = {
        "key_hex": named4["aii"]["key_hex"],
        "value_hex": hex_of(aii_bad),
    }
    rows4 = []
    base4, named4b, _ = _mode21_material_rows(
        include_aii=True, include_cleanup_plan=True
    )
    for r in base4:
        if _domain_subtype(r) == 0x34:
            rows4.append(named4["aii"])
        else:
            rows4.append(r)
    rows4 = sorted(rows4, key=lambda r: from_hex(r["key_hex"]))
    for r in rows4:
        st = _domain_subtype(r)
        if st == 0x20:
            named4["anchor"] = r
        elif st == 0x22:
            named4["state"] = r
        elif st == 0x31:
            named4["att"] = r
        elif st == 0x63:
            named4["cp"] = r
    calls4, exp4 = run_d3s2_mode21_att_index_pair_subject_raw_mismatch_corrupt(
        binding, rows4
    )
    vectors.append(
        {
            "id": "D3S2_M21_ATT_INDEX_PAIR_SUBJECT_RAW_MISMATCH",
            "kind": "mode21_att_index_pair_subject_raw_mismatch_corrupt",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows4),
            "alt_rows": {},
            "faults": [],
            "calls": calls4,
            "d1_refs": [
                D1_STATE_ID,
                D1_ATT_TX_ID,
                D1_AII_ID,
                D1_ANCHOR_ID,
                D1_CP_TX_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_TX_ID,
                row=named4["att"],
                expect_presence="PRESENT",
                note="TX ATTEMPT; primary proven before pair subject fail",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_AII_ID,
                row=named4["aii"],
                expect_presence="PRESENT",
                note=(
                    "ATTEMPT_ID_INDEX PRESENT at attempt_id key but body "
                    "transaction_id/subject mismatches ATT (pair raw/subject)"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named4["anchor"],
                    expect_presence="PRESENT",
                    note="true primary ANCHOR proven before pair fail",
                ),
                _d3s1.d1_ref_from_id(
                    D1_CP_TX_ID,
                    row=named4["cp"],
                    expect_presence="PRESENT",
                    note=(
                        "CLEANUP_PLAN PRESENT → cleanup_skip so wrong-txn AII "
                        "FOCUS undercount does not preempt BIND pair proof"
                    ),
                ),
            ],
            "notes": (
                "P0-D formal (§18.13.15 case 8 pair subject residual): Mode21 "
                "BIND_ATTEMPT proves STATE carrier + ANCHOR primary PVD/raw, "
                "then pair peer ATTEMPT_ID_INDEX is PRESENT at the attempt_id "
                "key but body transaction_id (and record_kd) mismatch the "
                "ATTEMPT subject → note_terminal_corrupt. CLEANUP_PLAN "
                "PRESENT so ordinary INDEX undercount is skipped. This is "
                "pair subject/raw mismatch only — not true-primary raw "
                "mismatch. Under D1 same-record validation and same "
                "READ_ONLY snapshot BIND, true-primary raw after "
                "PRESENT+typed validate is identity-tautological/"
                "unconstructible and is not claimed as P0-D coverage. "
                "BIND_INDEX must not run. abort; mutation_calls=0."
            ),
            "ownership": OWNERSHIP_P0D,
            "expected": exp4,
        }
    )

    if len(vectors) != D3S2_P0D_SLICE_COUNT:
        raise SystemExit("p0d slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P0D_KINDS:
        raise SystemExit(f"p0d kinds inventory mismatch: {kinds}")
    return vectors



# ---------------------------------------------------------------------------
# P1-A ordinary stream count under/over + empty-secondary (§18.13.15 #4/#14)
# CLEANUP_PLAN ABSENT only — not a cleanup_skip substitute for ordinary mismatch.
# ---------------------------------------------------------------------------


def _p1a_stream_fail_calls(mode: int, n_drive: int) -> List[Dict[str, Any]]:
    """begin + (n_drive-1) OK drives + last STORAGE_CORRUPT drive + abort."""
    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": mode, "expected_status": "OK"}
    ]
    for i in range(n_drive):
        if i + 1 == n_drive:
            calls.append(
                {
                    "op": "d3s2_drive",
                    "row_budget": 256,
                    "expected_status": "STORAGE_CORRUPT",
                }
            )
        else:
            calls.append(
                {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
            )
    calls.append({"op": "abort", "expected_status": "STORAGE_CORRUPT"})
    return calls


def _p1a_stream_fail_expected(
    *,
    n_ok: int,
    n_open: int,
    port_trace: List[str],
    domain_key_count: int,
    peer_gets: int,
    count_complete_mask: int,
    flags: int,
) -> Dict[str, Any]:
    return {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": domain_key_count,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": peer_gets,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_FAILED,
        "count_complete_mask": count_complete_mask,
        "binding_complete_mask": 0,
        "flags": flags,
    }


def _mode21_stream_count_material(
    *,
    cum: int,
    attempt_id: str,
    include_aii: bool = False,
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """ANCHOR + STATE(cum) + TX ATTEMPT [+ optional AII]; CLEANUP ABSENT.

    attempt_id: D1_ATT_TX_ID (COMMAND) or D1_ATT_TX_CAN_ID (CANCEL).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    att = cat[attempt_id]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_kd = _d3s1.key_digest(anchor_key)

    state_key = from_hex(state["key_hex"])
    state_val = _patch_state_cumulative_attempts(
        from_hex(state["value_hex"]), int(cum)
    )
    got_cum, state_txn = _parse_state_cum_and_txn(state_val)
    if got_cum != int(cum):
        raise SystemExit(f"Mode21 stream material cum={cum} self-check fail")

    att_key = from_hex(att["key_hex"])
    att_val = _d3s1.patch_pvd(from_hex(att["value_hex"]), anchor_pvd)
    (
        att_okind,
        att_oraw,
        att_id,
        att_txn,
        att_kind,
        att_pkd,
        att_pvd,
    ) = _parse_attempt_tx(att_val)
    if att_okind != ATT_OWNER_KIND_TRANSACTION:
        raise SystemExit("Mode21 stream material requires TX-owned ATTEMPT")
    if att_oraw != state_txn or att_txn != state_txn:
        raise SystemExit("Mode21 stream material ATT owner/txn mismatch")
    if att_pkd != anchor_kd or att_pvd != anchor_pvd:
        raise SystemExit("Mode21 stream material ATT pkd/PVD pin fail")
    if _d3s1.domain_value_framing(att_val) != "current":
        raise SystemExit("Mode21 stream material ATT framing not current")

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        },
        "state": {
            "key_hex": hex_of(state_key),
            "value_hex": hex_of(state_val),
        },
        "att": {"key_hex": hex_of(att_key), "value_hex": hex_of(att_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["anchor"],
        named["state"],
        named["att"],
    ]
    if include_aii:
        raise SystemExit("P1-A Mode21 stream material does not ship AII")

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    # Forbid CLEANUP_PLAN on ordinary path.
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x63:
            raise SystemExit("P1-A Mode21 material must not ship CLEANUP_PLAN")
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("P1-A Mode21 material must not ship AII")
    _ = att_kind
    _ = att_id
    return all_rows, named, anchor_pvd


def run_d3s2_mode21_app_attempt_stream_overcount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21: STATE cum=0 + COMMAND ATTEMPT → FOCUS_ATTEMPT A 1!=0 CORRUPT.

    Ordinary CLEANUP_PLAN ABSENT. declared A=B=C=0; observed A=1 at H2.
    BIND must not run. Independent reference model.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode21 app overcount expects 20 rows (17+3), got {n_ok}"
        )
    n_drive = 3
    n_open = 3
    walk = _walk_trace_segment(n_ok)
    calls = _p1a_stream_fail_calls(21, n_drive)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT: ANCHOR + STATE install + ATT residual
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE carrier
    port_trace.append("get")  # CANCEL_STATE ABSENT → B=0
    port_trace.append("get")  # CLEANUP_PLAN ABSENT → ordinary
    port_trace.append("iter_next")  # ATTEMPT residual
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT H2 overcount
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")
    expected = _p1a_stream_fail_expected(
        n_ok=n_ok,
        n_open=n_open,
        port_trace=port_trace,
        domain_key_count=3,
        peer_gets=2,
        count_complete_mask=0,
        flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    )
    _ = binding
    return calls, expected


def run_d3s2_mode21_cancel_attempt_stream_overcount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21: STATE cum=0 + CANCEL ATTEMPT only → FOCUS B 1!=0 CORRUPT.

    App lane observed A stays 0; not mixed with application overcount.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode21 cancel overcount expects 20 rows (17+3), got {n_ok}"
        )
    n_drive = 3
    n_open = 3
    walk = _walk_trace_segment(n_ok)
    calls = _p1a_stream_fail_calls(21, n_drive)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("get")  # CANCEL ABSENT → declared B=0
    port_trace.append("get")  # CLEANUP ABSENT
    port_trace.append("iter_next")  # CANCEL ATTEMPT residual
    port_trace.append("iter_next")  # NF
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("rollback")
    expected = _p1a_stream_fail_expected(
        n_ok=n_ok,
        n_open=n_open,
        port_trace=port_trace,
        domain_key_count=3,
        peer_gets=2,
        count_complete_mask=0,
        flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    )
    _ = binding
    return calls, expected


def run_d3s2_mode21_index_stream_undercount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21: STATE cum=1 + ATT, no AII, CLEANUP ABSENT → INDEX C 0!=1.

    FOCUS_ATTEMPT green (A=1 B=0); FOCUS_INDEX true EXHAUSTED undercount.
    Pair/BIND must not run. Not the CLEANUP_PLAN pair-absent path.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode21 INDEX undercount expects 20 rows (17+3), got {n_ok}"
        )
    n_drive = 4
    n_open = 4
    walk = _walk_trace_segment(n_ok)
    calls = _p1a_stream_fail_calls(21, n_drive)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("get")  # CANCEL
    port_trace.append("get")  # CLEANUP ABSENT
    port_trace.append("iter_next")  # ATT
    port_trace.append("iter_next")  # NF
    port_trace.append("iter_close")
    # FOCUS_ATTEMPT green
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # FOCUS_INDEX undercount
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("rollback")
    expected = _p1a_stream_fail_expected(
        n_ok=n_ok,
        n_open=n_open,
        port_trace=port_trace,
        domain_key_count=3,
        peer_gets=2,
        count_complete_mask=MASK_ATTEMPT,  # bit0 closed green; INDEX fail
        flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    )
    _ = binding
    return calls, expected


def _mode22_empty_secondary_material(
    *,
    rc_id: str,
    include_cs_too_late: bool,
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """DELIVERY + RESULT_CACHE [+ CS_TOO_LATE]; no DELIVERY-owned ATTEMPT."""
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    rc = cat[rc_id]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    dlv_draw, dlv_txn, _pid = _parse_delivery_raw_and_primary(dlv_val)

    rc_key = from_hex(rc["key_hex"])
    rc_val = _d3s1.patch_pvd(from_hex(rc["value_hex"]), dlv_pvd)
    app_n, rc_draw, rc_txn = _parse_rc_app_attempt_and_delivery(rc_val)
    if rc_draw != dlv_draw or rc_txn != dlv_txn:
        raise SystemExit("Mode22 empty-secondary RC/DELIVERY identity mismatch")
    if _d3s1.domain_value_framing(rc_val) != "current":
        raise SystemExit("Mode22 empty-secondary RC framing not current")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "rc": {"key_hex": hex_of(rc_key), "value_hex": hex_of(rc_val)},
    }
    domain_rows: List[Dict[str, str]] = [named["delivery"], named["rc"]]
    if include_cs_too_late:
        cs = cat[D1_CS_DLV_TOO_LATE_ID]
        named["cs"] = {
            "key_hex": cs["key_hex"],
            "value_hex": cs["value_hex"],
        }
        domain_rows.append(named["cs"])
        if app_n != 0:
            raise SystemExit(
                f"Mode22 CANCEL_FIRST undercount requires app=0, got {app_n}"
            )
    else:
        if app_n != 1:
            raise SystemExit(
                f"Mode22 APPLICATION_FIRST undercount requires app=1, got {app_n}"
            )

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = sorted(
        list(profile) + list(domain_rows), key=lambda r: from_hex(r["key_hex"])
    )
    for r in all_rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x31:
            raise SystemExit("Mode22 empty-secondary must not ship ATTEMPT")
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x63:
            raise SystemExit("Mode22 empty-secondary must not ship CLEANUP_PLAN")
    return all_rows, named, dlv_pvd


def run_d3s2_mode22_app_first_empty_secondary_undercount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22 case14 core: RC app=1 + DELIVERY, ATTEMPT band empty → A 0!=1.

    Carrier PRESENT + declared>0 + secondary empty; FOCUS_ATTEMPT H2 CORRUPT.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode22 app empty-secondary expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3
    walk = _walk_trace_segment(n_ok)
    calls = _p1a_stream_fail_calls(22, n_drive)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT: DLV residual + RC install + setup gets
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE carrier
    port_trace.append("get")  # CANCEL ABSENT → B=0
    port_trace.append("get")  # CLEANUP ABSENT
    port_trace.append("iter_next")  # NF
    port_trace.append("iter_close")
    # FOCUS empty secondary undercount
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("rollback")
    expected = _p1a_stream_fail_expected(
        n_ok=n_ok,
        n_open=n_open,
        port_trace=port_trace,
        domain_key_count=2,
        peer_gets=2,
        count_complete_mask=0,
        flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    )
    _ = binding
    return calls, expected


def run_d3s2_mode22_cancel_first_cancel_undercount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22 CANCEL_FIRST: app=0, CS non-zero caid → B=1, cancel ATT 0.

    FOCUS_ATTEMPT H2 B 0!=1 CORRUPT. Independent of application lane.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode22 cancel undercount expects 20 rows (17+3), got {n_ok}"
        )
    n_drive = 3
    n_open = 3
    walk = _walk_trace_segment(n_ok)
    calls = _p1a_stream_fail_calls(22, n_drive)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT: CS + DLV + RC install; CANCEL PRESENT → B=1
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # CANCEL_STATE residual
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE carrier
    port_trace.append("get")  # CANCEL PRESENT → declared B=1
    port_trace.append("get")  # CLEANUP ABSENT
    port_trace.append("iter_next")  # NF
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("rollback")
    expected = _p1a_stream_fail_expected(
        n_ok=n_ok,
        n_open=n_open,
        port_trace=port_trace,
        domain_key_count=3,
        peer_gets=2,
        count_complete_mask=0,
        flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    )
    _ = binding
    return calls, expected


def run_d3s2_mode26_mgmt_stream_overcount_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26: ES resume+discard=0 + same-tx MANAGEMENT 1 → A 1!=0 CORRUPT."""
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(
            f"mode26 mgmt overcount expects 20 rows (17+3), got {n_ok}"
        )
    n_drive = 3
    n_open = 3
    walk = _walk_trace_segment(n_ok)
    calls = _p1a_stream_fail_calls(26, n_drive)
    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # SELECT full residual (no Mode26 setup gets)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # FOCUS_MANAGEMENT overcount
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("rollback")
    expected = _p1a_stream_fail_expected(
        n_ok=n_ok,
        n_open=n_open,
        port_trace=port_trace,
        domain_key_count=3,
        peer_gets=0,
        count_complete_mask=0,
        flags=FLAG_BASELINE_DONE | FLAG_FOCUS_LIVE,
    )
    _ = binding
    return calls, expected


def build_d3s2_p1a_slice_vectors() -> List[Dict[str, Any]]:
    """P1-A append-only slice (6 vectors) after the frozen 119-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # 1) Mode21 application ATTEMPT overcount
    rows1, named1, _ = _mode21_stream_count_material(
        cum=0, attempt_id=D1_ATT_TX_ID
    )
    kind1 = _parse_attempt_tx(from_hex(named1["att"]["value_hex"]))[4]
    if kind1 != ATT_KIND_COMMAND:
        raise SystemExit("P1-A app overcount requires COMMAND ATTEMPT")
    cum1, _ = _parse_state_cum_and_txn(from_hex(named1["state"]["value_hex"]))
    if cum1 != 0:
        raise SystemExit("P1-A app overcount requires STATE cum=0")
    calls1, exp1 = run_d3s2_mode21_app_attempt_stream_overcount_corrupt(
        binding, rows1
    )
    vectors.append(
        {
            "id": "D3S2_M21_APP_ATTEMPT_STREAM_OVERCOUNT",
            "kind": "mode21_app_attempt_stream_overcount_corrupt",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows1),
            "alt_rows": {},
            "faults": [],
            "calls": calls1,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named1["state"],
                expect_presence="PRESENT",
                note="carrier STATE cumulative_attempts=0 (declared A=0 B=0 C=0)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ATT_TX_ID,
                row=named1["att"],
                expect_presence="PRESENT",
                note="TX COMMAND ATTEMPT overcount secondary (observed A=1)",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named1["anchor"],
                    expect_presence="PRESENT",
                    note="true primary identity for ATT pkd/PVD D1 material",
                )
            ],
            "notes": (
                "P1-A formal (§18.13.15 case 4): Mode21 application ATTEMPT "
                "stream overcount — CLEANUP_PLAN ABSENT ordinary path; STATE "
                "declares A=0/B=0/C=0; matching TX COMMAND ATTEMPT present; "
                "FOCUS_ATTEMPT true EXHAUSTED H2 observes A=1>0 → "
                "note_terminal_corrupt STORAGE_CORRUPT. FOCUS_INDEX/BIND must "
                "not run. Single READ_ONLY txn; abort; mutation_calls=0; "
                "faults=[]. Independent Python only."
            ),
            "ownership": OWNERSHIP_P1A,
            "expected": exp1,
        }
    )

    # 2) Mode21 cancel ATTEMPT overcount
    rows2, named2, _ = _mode21_stream_count_material(
        cum=0, attempt_id=D1_ATT_TX_CAN_ID
    )
    kind2 = _parse_attempt_tx(from_hex(named2["att"]["value_hex"]))[4]
    if kind2 != ATT_KIND_CANCEL:
        raise SystemExit("P1-A cancel overcount requires CANCEL ATTEMPT")
    calls2, exp2 = run_d3s2_mode21_cancel_attempt_stream_overcount_corrupt(
        binding, rows2
    )
    vectors.append(
        {
            "id": "D3S2_M21_CANCEL_ATTEMPT_STREAM_OVERCOUNT",
            "kind": "mode21_cancel_attempt_stream_overcount_corrupt",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows2),
            "alt_rows": {},
            "faults": [],
            "calls": calls2,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_CAN_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named2["state"],
                expect_presence="PRESENT",
                note="carrier STATE cum=0; CANCEL_STATE ABSENT → declared B=0",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ATT_TX_CAN_ID,
                row=named2["att"],
                expect_presence="PRESENT",
                note="TX CANCEL ATTEMPT only (observed B=1; app lane A=0)",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named2["anchor"],
                    expect_presence="PRESENT",
                    note="true primary identity for ATT material",
                )
            ],
            "notes": (
                "P1-A formal (§18.13.15 case 4 cancel lane): Mode21 cancel "
                "ATTEMPT stream overcount — CLEANUP_PLAN ABSENT; declared B=0 "
                "(CANCEL_STATE ABSENT); one TX CANCEL ATTEMPT; FOCUS_ATTEMPT "
                "H2 observes B=1!=0 → STORAGE_CORRUPT. Not mixed with "
                "application ATTEMPT lane. abort; mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1A,
            "expected": exp2,
        }
    )

    # 3) Mode21 INDEX undercount (ordinary; no CLEANUP)
    rows3, named3, _ = _mode21_stream_count_material(
        cum=1, attempt_id=D1_ATT_TX_ID
    )
    cum3, _ = _parse_state_cum_and_txn(from_hex(named3["state"]["value_hex"]))
    if cum3 != 1:
        raise SystemExit("P1-A INDEX undercount requires STATE cum=1")
    calls3, exp3 = run_d3s2_mode21_index_stream_undercount_corrupt(
        binding, rows3
    )
    vectors.append(
        {
            "id": "D3S2_M21_INDEX_STREAM_UNDERCOUNT",
            "kind": "mode21_index_stream_undercount_corrupt",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows3),
            "alt_rows": {},
            "faults": [],
            "calls": calls3,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named3["state"],
                expect_presence="PRESENT",
                note="carrier STATE cum=1 → declared A=1 B=0 C=1; CLEANUP ABSENT",
            ),
            "peer_ref": _d3s1.none_ref(
                "ATTEMPT_ID_INDEX ABSENT in secondary band (INDEX undercount)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ATT_TX_ID,
                    row=named3["att"],
                    expect_presence="PRESENT",
                    note="matching app ATTEMPT so FOCUS_ATTEMPT stays green",
                ),
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named3["anchor"],
                    expect_presence="PRESENT",
                    note="true primary identity; BIND must not run",
                ),
            ],
            "notes": (
                "P1-A formal (§18.13.15 case 4 INDEX lane): Mode21 ordinary "
                "INDEX undercount — STATE A=1/B=0/C=1 + matching COMMAND "
                "ATTEMPT; no AII; CLEANUP_PLAN ABSENT (not cleanup_skip). "
                "FOCUS_ATTEMPT H2 green (A=1 B=0); FOCUS_INDEX true EXHAUSTED "
                "observes C=0!=1 → STORAGE_CORRUPT. Pair/BIND must not run. "
                "Distinct from D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT "
                "(CLEANUP skip path). abort; mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1A,
            "expected": exp3,
        }
    )

    # 4) Mode22 APPLICATION_FIRST empty-secondary undercount (case14 core)
    rows4, named4, _ = _mode22_empty_secondary_material(
        rc_id=D1_RC_ID, include_cs_too_late=False
    )
    app4, _, _ = _parse_rc_app_attempt_and_delivery(
        from_hex(named4["rc"]["value_hex"])
    )
    if app4 != 1:
        raise SystemExit("P1-A Mode22 app undercount requires app=1")
    calls4, exp4 = run_d3s2_mode22_app_first_empty_secondary_undercount_corrupt(
        binding, rows4
    )
    vectors.append(
        {
            "id": "D3S2_M22_APP_FIRST_EMPTY_SECONDARY_UNDERCOUNT",
            "kind": "mode22_app_first_empty_secondary_undercount_corrupt",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows4),
            "alt_rows": {},
            "faults": [],
            "calls": calls4,
            "d1_refs": [D1_RC_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named4["rc"],
                expect_presence="PRESENT",
                note=(
                    "carrier RESULT_CACHE application_attempt_count=1 "
                    "(APPLICATION_FIRST; declared A=1)"
                ),
            ),
            "peer_ref": _d3s1.none_ref(
                "DELIVERY-owned ATTEMPT band empty (secondary undercount)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named4["delivery"],
                    expect_presence="PRESENT",
                    note="D1-valid true primary material; BIND must not run",
                )
            ],
            "notes": (
                "P1-A formal (§18.13.15 case 14 core): Mode22 APPLICATION_FIRST "
                "empty-secondary undercount — RESULT_CACHE carrier PRESENT with "
                "application_attempt_count=1 and DELIVERY primary material; "
                "DELIVERY-owned ATTEMPT band empty; CLEANUP_PLAN ABSENT. "
                "FOCUS_ATTEMPT H2 observes A=0!=1 → STORAGE_CORRUPT. BIND must "
                "not run. abort; mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1A,
            "expected": exp4,
        }
    )

    # 5) Mode22 CANCEL_FIRST cancel undercount (case4 cancel lane)
    rows5, named5, _ = _mode22_empty_secondary_material(
        rc_id=D1_RC_CANCEL_FIRST_ID, include_cs_too_late=True
    )
    app5, _, _ = _parse_rc_app_attempt_and_delivery(
        from_hex(named5["rc"]["value_hex"])
    )
    if app5 != 0:
        raise SystemExit("P1-A Mode22 cancel undercount requires app=0")
    calls5, exp5 = run_d3s2_mode22_cancel_first_cancel_undercount_corrupt(
        binding, rows5
    )
    vectors.append(
        {
            "id": "D3S2_M22_CANCEL_FIRST_CANCEL_UNDERCOUNT",
            "kind": "mode22_cancel_first_cancel_undercount_corrupt",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows5),
            "alt_rows": {},
            "faults": [],
            "calls": calls5,
            "d1_refs": [D1_RC_CANCEL_FIRST_ID, D1_DLV_ID, D1_CS_DLV_TOO_LATE_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_CANCEL_FIRST_ID,
                row=named5["rc"],
                expect_presence="PRESENT",
                note="carrier RESULT_CACHE app=0 (CANCEL_FIRST shape)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_CS_DLV_TOO_LATE_ID,
                row=named5["cs"],
                expect_presence="PRESENT",
                note=(
                    "DLV CANCEL_STATE non-zero cancel_attempt_id → declared B=1"
                ),
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named5["delivery"],
                    expect_presence="PRESENT",
                    note="D1-valid DELIVERY; ATTEMPT band empty",
                )
            ],
            "notes": (
                "P1-A formal (§18.13.15 case 4 Mode22 cancel lane): CANCEL_FIRST "
                "carrier declares app=0 and cancel B=1 via DLV CANCEL_STATE "
                "(non-zero cancel_attempt_id; not app==0 heuristic); cancel "
                "ATTEMPT 0. FOCUS_ATTEMPT H2 observes B=0!=1 → STORAGE_CORRUPT. "
                "CLEANUP_PLAN ABSENT. abort; mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1A,
            "expected": exp5,
        }
    )

    # 6) Mode26 MANAGEMENT overcount
    rows6, named6, _ = _mode26_material_rows(
        include_es=True, resume=0, discard=0
    )
    es_r, es_d = _parse_es_resume_discard(from_hex(named6["es"]["value_hex"]))
    if es_r != 0 or es_d != 0:
        raise SystemExit("P1-A Mode26 overcount requires ES resume+discard=0")
    calls6, exp6 = run_d3s2_mode26_mgmt_stream_overcount_corrupt(binding, rows6)
    vectors.append(
        {
            "id": "D3S2_M26_MGMT_STREAM_OVERCOUNT",
            "kind": "mode26_mgmt_stream_overcount_corrupt",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows6),
            "alt_rows": {},
            "faults": [],
            "calls": calls6,
            "d1_refs": [D1_ES_ID, D1_ML_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ES_ID,
                row=named6["es"],
                expect_presence="PRESENT",
                note="carrier EVENT_SPOOL resume+discard=0 (declared A=0)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ML_ID,
                row=named6["mgmt"],
                expect_presence="PRESENT",
                note="same-tx MANAGEMENT RESUME overcount secondary (observed A=1)",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named6["anchor"],
                    expect_presence="PRESENT",
                    note="true primary identity; BIND must not run",
                )
            ],
            "notes": (
                "P1-A formal (§18.13.15 case 4 Mode26): MANAGEMENT stream "
                "overcount — EVENT_SPOOL declares successful_resume_count+"
                "discard_committed=0; one same-tx MANAGEMENT RESUME present; "
                "FOCUS_MANAGEMENT H2 observes A=1>0 → STORAGE_CORRUPT. "
                "abort; mutation_calls=0; faults=[]. Independent Python only."
            ),
            "ownership": OWNERSHIP_P1A,
            "expected": exp6,
        }
    )

    if len(vectors) != D3S2_P1A_SLICE_COUNT:
        raise SystemExit("p1a slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1A_KINDS:
        raise SystemExit(f"p1a kinds inventory mismatch: {kinds}")
    return vectors


# ---------------------------------------------------------------------------
# P1-D: profile mismatch / future_profile evaluator-off (§18.13.15 case12)
# ---------------------------------------------------------------------------


def _from_hex_local(h: str) -> bytes:
    return _d3s1.from_hex(h)


def _be32_local(v: int) -> bytes:
    return _d3s1.be32(v)


def _crc32c_local(b: bytes) -> int:
    return _d3s1.crc32c(b)


def _hex_of_local(b: bytes) -> str:
    return _d3s1.hex_of(b)


def run_d3s2_profile_evaluator_off(
    binding: Dict[str, Any],
    rows: List[Dict[str, str]],
    *,
    profile_mismatch: int,
    future_profile_candidate: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Independent reference model: Mode21 baseline-only evaluator-off.

    begin → one baseline drive to true EXHAUSTED → finalize UNSUPPORTED.
    phase stays BASELINE; flags == BASELINE_DONE only; masks 0; no INTERNAL
    reopen / BIND / peer get. Not COMPLETE/COMPLETE_READY (false authority).
    Does not invoke production C.
    """
    if profile_mismatch not in (0, 1) or future_profile_candidate not in (0, 1):
        raise SystemExit("profile flags must be 0|1")
    if profile_mismatch == future_profile_candidate:
        raise SystemExit("exactly one of mismatch/future must be set")
    if profile_mismatch + future_profile_candidate != 1:
        raise SystemExit("profile flag mutual exclusion")
    n_ok = len(rows)
    if n_ok < 18:
        raise SystemExit("evaluator-off rows must include domain material")
    # 17 catalog + ≥1 domain; family14 ok count is 17; domain not decoded.
    domain_n = n_ok - 17
    if domain_n < 1:
        raise SystemExit("domain rows required")

    calls: List[Dict[str, Any]] = [
        {
            "op": "begin_profiled_d3s2",
            "mode": 21,
            "expected_status": "OK",
        },
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "OK",
        },
        {"op": "finalize", "expected_status": "UNSUPPORTED"},
    ]

    port_trace: List[str] = _begin_profile_port_prefix()
    port_trace.append("iter_open:prefix0")
    port_trace.extend(_walk_trace_segment(n_ok))
    port_trace.append("iter_close")
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "UNSUPPORTED",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 0,
        "ok_row_count": n_ok,
        "profile_exact_active": 0,
        "profile_mismatch": profile_mismatch,
        "future_profile_candidate": future_profile_candidate,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": 1,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": 0,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_BASELINE,
        "count_complete_mask": 0,
        "binding_complete_mask": 0,
        "flags": FLAG_BASELINE_DONE,
    }
    # Material sanity: candidate encoding is always exact binding fields;
    # stored rows differ by mismatch mutation or future version.
    if binding is None:
        raise SystemExit("binding required")
    return calls, expected


def build_d3s2_p1d_slice_vectors() -> List[Dict[str, Any]]:
    """Append-only P1-D Mode21 profile mismatch / future evaluator-off."""
    _assert_d1_authority_pin()
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # Domain material (D1 STATE + ANCHOR) so ordinary S2 would have work.
    state_row = _d3s1.row_from_d1(D1_STATE_ID)
    anchor_row = _d3s1.row_from_d1(D1_ANCHOR_ID)

    # 1) profile_mismatch: stored binding byte flip + CRC (candidate exact).
    mismatch_rows = _d3s1.encode_all_profile_rows(binding)
    bind = bytearray(_from_hex_local(mismatch_rows[0]["value_hex"]))
    bind[50] ^= 0x01
    body = bytes(bind[:-4])
    bind[-4:] = _be32_local(_crc32c_local(body))
    mismatch_rows[0]["value_hex"] = _hex_of_local(bytes(bind))
    rows_mm = _d3s1.merge_rows(mismatch_rows, [state_row, anchor_row])
    calls_mm, exp_mm = run_d3s2_profile_evaluator_off(
        binding,
        rows_mm,
        profile_mismatch=1,
        future_profile_candidate=0,
    )
    vectors.append(
        {
            "id": "D3S2_M21_PROFILE_MISMATCH_EVALUATOR_OFF",
            "kind": "mode21_profile_mismatch_evaluator_off_unsupported",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_mm),
            "alt_rows": {},
            "faults": [],
            "calls": calls_mm,
            "d1_refs": [D1_STATE_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=state_row,
                expect_presence="PRESENT",
                note=(
                    "domain STATE present; S2 evaluator never starts under "
                    "profile_mismatch"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=anchor_row,
                expect_presence="PRESENT",
                note="domain ANCHOR present; no BIND/peer get",
            ),
            "row_refs": [],
            "notes": (
                "P1-D formal (§18.13.15 case12): Mode21 profile_mismatch "
                "evaluator-off — stored binding semantic mismatch (CRC-valid) "
                "vs exact candidate; domain STATE+ANCHOR present. Baseline "
                "zero-prefix once → EXHAUSTED; phase stays BASELINE with "
                "BASELINE_DONE only (not COMPLETE/COMPLETE_READY); masks 0; "
                "no INTERNAL reopen/BIND/peer get; finalize UNSUPPORTED "
                "adopted0. Not future_profile_candidate / not "
                "recognizable_future_seen. mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1D,
            "expected": exp_mm,
        }
    )

    # 2) future_profile_candidate: stored binding record_version=2.
    future_rows = _d3s1.encode_all_profile_rows(binding, binding_version=2)
    rows_fp = _d3s1.merge_rows(future_rows, [state_row, anchor_row])
    calls_fp, exp_fp = run_d3s2_profile_evaluator_off(
        binding,
        rows_fp,
        profile_mismatch=0,
        future_profile_candidate=1,
    )
    vectors.append(
        {
            "id": "D3S2_M21_FUTURE_PROFILE_EVALUATOR_OFF",
            "kind": "mode21_future_profile_evaluator_off_unsupported",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_fp),
            "alt_rows": {},
            "faults": [],
            "calls": calls_fp,
            "d1_refs": [D1_STATE_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=state_row,
                expect_presence="PRESENT",
                note=(
                    "domain STATE present; S2 evaluator never starts under "
                    "future_profile_candidate"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=anchor_row,
                expect_presence="PRESENT",
                note="domain ANCHOR present; no BIND/peer get",
            ),
            "row_refs": [],
            "notes": (
                "P1-D formal (§18.13.15 case12): Mode21 future_profile_candidate "
                "evaluator-off — stored binding NLR1 record_version=2 "
                "(validate_snapshot UNSUPPORTED class); candidate exact v1; "
                "domain STATE+ANCHOR present. Baseline zero-prefix once → "
                "EXHAUSTED; phase BASELINE + BASELINE_DONE only; masks 0; no "
                "INTERNAL reopen/BIND/peer get; finalize UNSUPPORTED "
                "adopted0. Distinct from profile_mismatch and from "
                "recognizable_future_seen. mutation_calls=0; faults=[]."
            ),
            "ownership": OWNERSHIP_P1D,
            "expected": exp_fp,
        }
    )

    if len(vectors) != D3S2_P1D_SLICE_COUNT:
        raise SystemExit("p1d slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1D_KINDS:
        raise SystemExit(f"p1d kinds inventory mismatch: {kinds}")
    # Fail-closed: mismatch vs future must not share stored binding shape.
    if vectors[0]["rows"][0]["value_hex"] == vectors[1]["rows"][0]["value_hex"]:
        raise SystemExit("p1d mismatch/future stored binding must differ")
    return vectors


def run_d3s2_mode21_count_green_bind_incomplete_false_terminal(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode21 count-green without BIND set + false-terminal probe then COMPLETE.

    Independent reference model (docs/17 §18.13.4/.9/.10/.15 case10):
      Same success material as Mode21 STATE+ATT+AII+ANCHOR. Drive through
      FOCUS_ATTEMPT+FOCUS_INDEX (count bit0|bit1) and empty SELECT → enter
      BIND_ATTEMPT with binding_complete_mask=0, BIND_PHASE_ACTIVE,
      COMPLETE_READY clear, sticky 0. Call-level checkpoint freezes that
      exact shape. Test-only probe_false_terminal_finalize (not a Port op)
      expects INVALID_STATE (bridge: session/context copy + EXHAUSTED).
      Resume original BIND_ATTEMPT+BIND_INDEX → COMPLETE → finalize adopt1.
      Port-trace equals ordinary Mode21 success (probe is Port 0).
    """
    n_ok = len(rows)
    if n_ok != 21:
        raise SystemExit(
            f"mode21 count-green bind-incomplete expects 21 rows, got {n_ok}"
        )
    # STATE carrier complete key (last_carrier_key at BIND entry).
    state_rows = [
        r
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    if len(state_rows) != 1:
        raise SystemExit(
            f"mode21 count-green expects exact 1 STATE carrier, got "
            f"{len(state_rows)}"
        )
    state_key = from_hex(state_rows[0]["key_hex"])
    state_key_len = len(state_key)
    if state_key_len == 0 or state_key_len > 45:
        raise SystemExit(f"STATE carrier key_len invalid: {state_key_len}")

    n_drive = 7
    n_open = 7
    walk = _walk_trace_segment(n_ok)

    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier + setup gets + reopen FOCUS
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("get")  # CANCEL_STATE ABSENT
    port_trace.append("get")  # CLEANUP_PLAN ABSENT
    port_trace.append("iter_next")  # ATTEMPT residual
    port_trace.append("iter_next")  # AII residual
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT H2
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 FOCUS_INDEX H2 → count bit0|bit1 complete
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 SELECT empty → BIND_ATTEMPT entry reopen (count green, bind 0)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    port_trace.append("iter_open:prefix0")  # BIND stream reopen (still pre-walk)
    cp_trace_count = len(port_trace)
    # drive6 BIND_ATTEMPT
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATTEMPT secondary
    port_trace.append("get")  # STATE carrier
    port_trace.append("get")  # ANCHOR primary
    port_trace.append("get")  # INDEX pair PRESENT
    port_trace.append("iter_next")  # AII
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive7 BIND_INDEX
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("iter_next")  # AII secondary
    port_trace.append("get")  # ANCHOR primary
    port_trace.append("get")  # ATTEMPT pair PRESENT
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    # Spy counts at BIND entry checkpoint (after drive5 + BIND reopen):
    # begin open + SELECT + FOCUS_ATT + FOCUS_IDX + SELECT empty + BIND = 6;
    # five closes (baseline/SELECT/FOCUS×2/SELECT empty); begin_calls=1.
    checkpoint_drive: Dict[str, Any] = {
        "op": "d3s2_drive",
        "row_budget": 256,
        "expected_status": "OK",
        "has_checkpoint": 1,
        "cp_phase": PHASE_BIND_ATTEMPT,
        "cp_focus_live": 0,
        "cp_observed_a": 0,
        "cp_observed_b": 0,
        "cp_observed_c": 0,
        "cp_count_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "cp_binding_complete_mask": 0,
        "cp_flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
        "cp_pass_kind": PASS_INTERNAL,
        "cp_cleanup_skip": 0,
        "cp_last_carrier_key_len": state_key_len,
        "cp_last_carrier_key_hex": hex_of(state_key),
        "cp_begin_calls": 1,
        "cp_iter_open_calls": 6,
        "cp_iter_close_calls": 5,
        "cp_trace_count": cp_trace_count,
    }
    if (int(checkpoint_drive["cp_flags"]) & FLAG_COMPLETE_READY) != 0:
        raise SystemExit("count-green checkpoint must not set COMPLETE_READY")
    if int(checkpoint_drive["cp_count_complete_mask"]) != (
        MASK_ATTEMPT | MASK_INDEX
    ):
        raise SystemExit("count-green checkpoint count mask must be full mode21")
    if int(checkpoint_drive["cp_binding_complete_mask"]) != 0:
        raise SystemExit("count-green checkpoint binding mask must be 0")
    if int(checkpoint_drive["cp_phase"]) != PHASE_BIND_ATTEMPT:
        raise SystemExit("count-green checkpoint phase must be BIND_ATTEMPT")
    if int(checkpoint_drive["cp_trace_count"]) != 141:
        raise SystemExit(
            f"count-green cp_trace_count pin fail: "
            f"{checkpoint_drive['cp_trace_count']}"
        )

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 21, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        checkpoint_drive,
        {
            "op": "probe_false_terminal_finalize",
            "expected_status": "INVALID_STATE",
        },
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "finalize", "expected_status": "OK"},
    ]
    if sum(1 for c in calls if c["op"] == "d3s2_drive") != n_drive:
        raise SystemExit("mode21 count-green drive count drift")
    if sum(1 for c in calls if c["op"] == "probe_false_terminal_finalize") != 1:
        raise SystemExit("mode21 count-green requires exactly one false-terminal probe")
    # Probe must sit after BIND-entry checkpoint and before BIND walks resume.
    ops = [c["op"] for c in calls]
    cp_i = next(
        i
        for i, c in enumerate(calls)
        if c["op"] == "d3s2_drive" and int(c.get("has_checkpoint", 0)) == 1
    )
    probe_i = ops.index("probe_false_terminal_finalize")
    if probe_i != cp_i + 1:
        raise SystemExit("false-terminal probe must immediately follow checkpoint")
    if ops.count("finalize") != 1 or ops[-1] != "finalize":
        raise SystemExit("must end with single success finalize")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 4,
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": 7,
        "d3_mode_applicable_count": 2,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "binding_complete_mask": MASK_ATTEMPT | MASK_INDEX,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("count-green port_trace must be single-txn")
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("count-green rows must be key-sorted")
    aii_n = sum(
        1
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x34
    )
    cp_n = sum(
        1
        for r in rows
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x63
    )
    if aii_n != 1:
        raise SystemExit(f"count-green must ship exact 1 AII, got {aii_n}")
    if cp_n != 0:
        raise SystemExit("count-green ordinary path must not ship CLEANUP_PLAN")
    _ = binding
    return calls, expected


def build_d3s2_p1d2_slice_vectors() -> List[Dict[str, Any]]:
    """Append-only P1-D2 Mode21 count-green without BIND finalize anti-pass."""
    _assert_d1_authority_pin()
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    rows, named, _pvd = _mode21_material_rows(
        include_aii=True, include_cleanup_plan=False
    )
    calls, exp = run_d3s2_mode21_count_green_bind_incomplete_false_terminal(
        binding, rows
    )
    # Fail-closed structural pins before publish.
    cp_calls = [
        c for c in calls if int(c.get("has_checkpoint", 0)) == 1
    ]
    if len(cp_calls) != 1:
        raise SystemExit("P1-D2 expects exactly one checkpoint call")
    cp = cp_calls[0]
    if int(cp["cp_count_complete_mask"]) != (MASK_ATTEMPT | MASK_INDEX):
        raise SystemExit("P1-D2 checkpoint count mask must be green")
    if int(cp["cp_binding_complete_mask"]) != 0:
        raise SystemExit("P1-D2 checkpoint binding mask must be incomplete")
    if int(cp["cp_phase"]) != PHASE_BIND_ATTEMPT:
        raise SystemExit("P1-D2 checkpoint phase must be BIND_ATTEMPT")
    if (int(cp["cp_flags"]) & FLAG_COMPLETE_READY) != 0:
        raise SystemExit("P1-D2 checkpoint must not set COMPLETE_READY")
    if (int(cp["cp_flags"]) & FLAG_BIND_PHASE_ACTIVE) == 0:
        raise SystemExit("P1-D2 checkpoint must set BIND_PHASE_ACTIVE")
    if sum(1 for c in calls if c["op"] == "probe_false_terminal_finalize") != 1:
        raise SystemExit("P1-D2 requires probe_false_terminal_finalize")
    if exp.get("final_status") != "OK" or int(exp.get("adopted", 0)) != 1:
        raise SystemExit("P1-D2 must resume to COMPLETE/adopt1")
    if int(exp.get("binding_complete_mask", 0)) != (MASK_ATTEMPT | MASK_INDEX):
        raise SystemExit("P1-D2 terminal binding mask must be complete")
    if int(exp.get("phase", -1)) != PHASE_COMPLETE:
        raise SystemExit("P1-D2 terminal phase must be COMPLETE")

    vectors.append(
        {
            "id": "D3S2_M21_COUNT_GREEN_BIND_INCOMPLETE_FALSE_TERMINAL_OK",
            "kind": "mode21_count_green_bind_incomplete_false_terminal_ok",
            "mode": 21,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows),
            "alt_rows": {},
            "faults": [],
            "calls": calls,
            "d1_refs": [D1_STATE_ID, D1_ATT_TX_ID, D1_AII_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named["state"],
                expect_presence="PRESENT",
                note=(
                    "Mode21 carrier TRANSACTION_STATE cum=1; last_carrier_key "
                    "at count-green BIND_ATTEMPT entry checkpoint"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR; BIND not yet complete at probe",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ATT_TX_ID,
                    row=named["att"],
                    expect_presence="PRESENT",
                    note="TX COMMAND ATTEMPT; FOCUS count green before BIND",
                ),
                _d3s1.d1_ref_from_id(
                    D1_AII_ID,
                    row=named["aii"],
                    expect_presence="PRESENT",
                    note="INDEX secondary; FOCUS count green before BIND",
                ),
            ],
            "notes": (
                "P1-D2 formal (§18.13.15 case10): Mode21 count-green without "
                "BIND set. Same ordinary success material as "
                "D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK. After FOCUS_"
                "ATTEMPT+FOCUS_INDEX H2, count_complete_mask=bit0|bit1 while "
                "binding_complete_mask=0; phase=BIND_ATTEMPT with "
                "BIND_PHASE_ACTIVE (no COMPLETE_READY), sticky 0, "
                "focus_live 0. Call-level checkpoint freezes phase/masks/"
                "flags/pass_kind/cleanup_skip/last_carrier_key (STATE) and "
                "spy begin/iter_open/iter_close/trace_count. Test-only "
                "probe_false_terminal_finalize (session/context copy, "
                "copy.state=EXHAUSTED) expects finalize INVALID_STATE with "
                "Port 0 / no cleanup / no out_result mutation — proves "
                "incomplete COMPLETE gate, not OPEN-state reject alone. "
                "Original session resumes BIND_ATTEMPT+BIND_INDEX → "
                "COMPLETE/adopt1. Not missing-peer CORRUPT, not Port "
                "fault, not evaluator-off, not metadata-only. Single "
                "READ_ONLY txn; mutation_calls=0; faults=[]. Independent "
                "Python only."
            ),
            "ownership": OWNERSHIP_P1D2,
            "expected": exp,
        }
    )

    if len(vectors) != D3S2_P1D2_SLICE_COUNT:
        raise SystemExit("p1d2 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_P1D2_KINDS:
        raise SystemExit(f"p1d2 kinds inventory mismatch: {kinds}")
    return vectors


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "generate":
        if len(argv) != 3:
            print("usage: generate <path>", file=sys.stderr)
            return 2
        generate(Path(argv[2]))
        return 0
    if cmd == "check":
        if len(argv) != 3:
            print("usage: check <path>", file=sys.stderr)
            return 2
        return check(Path(argv[2]))
    if cmd == "emit-c-fixture":
        if len(argv) != 4:
            print("usage: emit-c-fixture <json> <header>", file=sys.stderr)
            return 2
        emit_c_fixture(Path(argv[2]), Path(argv[3]))
        return 0
    if cmd == "self-test":
        return self_test()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
