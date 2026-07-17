#!/usr/bin/env python3
"""U5/U6 Normative docs gate — immutability / freshness of review-accepted bytes.

This is NOT a natural-language semantic / NLP classifier and is NOT a substitute
for human review. Safety claims about prose synonyms are out of scope.

Authority:
  1) versioned freeze manifest (spec/frozen/u5-u6-normative-freeze-v1.json)
  2) SHA-256 of that manifest pinned in this file (PINNED_FREEZE_SHA256)
  3) exact byte pins of docs/25, docs/26, ADR-0005, ADR-0006
  4) exact L6 algorithm fence body + machine-readable constraints from the freeze
  5) retained structural layout / state checks (arithmetic, CRC rows, REL_HOLD, …)

Legitimate freeze change requires: new freeze version, Accepted ADR, independent
re-review, and an explicit update of the pin constants in this gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import stat as stat_mod
import sys
import tempfile
from typing import Any, Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Hard pins (must change only with deliberate freeze re-acceptance)
# ---------------------------------------------------------------------------
PINNED_FREEZE_RELPATH = "spec/frozen/u5-u6-normative-freeze-v1.json"
PINNED_FREEZE_ID = "u5-u6-normative-freeze"
PINNED_FREEZE_VERSION = "1"
PINNED_FREEZE_SHA256 = (
    "71750e9a7ce2f9298a9bd77012d1f1601864323c5ce959de071b9ee6f6ad5cbc"
)
PINNED_HASH_ALGORITHM = "SHA-256"
# Self-test only: when set, load_freeze accepts this digest instead of PINNED_FREEZE_SHA256
# so deep content validators (path traversal, phase swap, …) can be exercised.
_TEST_PIN_OVERRIDE: str | None = None
ALLOWED_DOC_PATHS = frozenset(
    {
        "docs/25-u5-cell-operating-assignment.md",
        "docs/26-u6-transport-custody.md",
        "docs/adr/0005-u5-cell-operating-assignment-control-v2.md",
        "docs/adr/0006-u6-transport-custody.md",
    }
)
FREEZE_TOP_KEYS = frozenset(
    {
        "freeze_id",
        "freeze_version",
        "schema_version",
        "description",
        "hash_algorithm",
        "documents",
        "l6_algorithm",
        "authority_prose_required_in_u5",
    }
)
L6_ALG_KEYS = frozenset(
    {
        "source_path",
        "section_marker",
        "fence_language",
        "body",
        "body_byte_length",
        "body_sha256",
        "ordered_phases",
        "declarations",
        "constraints",
    }
)


class Paths:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.u5 = root / "docs" / "25-u5-cell-operating-assignment.md"
        self.u6 = root / "docs" / "26-u6-transport-custody.md"
        self.adr5 = root / "docs" / "adr" / "0005-u5-cell-operating-assignment-control-v2.md"
        self.adr6 = root / "docs" / "adr" / "0006-u6-transport-custody.md"
        self.doc05 = root / "docs" / "05-security-and-compliance.md"
        self.doc07 = root / "docs" / "07-testing-and-quality.md"
        self.doc23 = root / "docs" / "23-usb-radio-boundary.md"
        self.freeze = root / PINNED_FREEZE_RELPATH


P = Paths(REPO_ROOT)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def read_bytes(path: pathlib.Path) -> bytes:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_bytes()


def require_contains(text: str, needle: str, where: str) -> None:
    if needle not in text:
        fail(f"{where} must contain {needle!r}")


def require_absent(text: str, needle: str, where: str) -> None:
    if needle in text:
        fail(f"{where} must not contain {needle!r}")


def section_between(text: str, start: str, end: str, where: str) -> str:
    i = text.find(start)
    if i < 0:
        fail(f"{where}: missing {start!r}")
    j = text.find(end, i + len(start))
    if j < 0:
        fail(f"{where}: missing end {end!r}")
    return text[i:j]


def first_text_fence(section: str, where: str) -> str:
    m = re.search(r"```text\n(.*?)```", section, re.S)
    if not m:
        fail(f"{where}: missing ```text fence table")
    return m.group(1)


def parse_ose_rows(table: str) -> list[tuple[int, int, int, str]]:
    rows: list[tuple[int, int, int, str]] = []
    for line in table.splitlines():
        m = re.match(r"^(\d+)\s+(\d+)\s+(\d+)\s+(\S+.*)$", line.strip())
        if m:
            rows.append((int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)))
    return rows


def check_layout(rows: list[tuple[int, int, int, str]], title: str, expected_end: int) -> None:
    if not rows:
        fail(f"{title}: no layout rows")
    for o, s, e, _ in rows:
        if o + s != e:
            fail(f"{title}: {o}+{s}!={e}")
    for i in range(1, len(rows)):
        if rows[i][0] != rows[i - 1][2]:
            fail(f"{title}: gap/overlap {rows[i-1][:3]} -> {rows[i][:3]}")
    if rows[0][0] != 0:
        fail(f"{title}: must start at 0")
    if rows[-1][2] != expected_end:
        fail(f"{title}: end {rows[-1][2]} != {expected_end}")


def crc_from_table_row(table: str, field_substr: str, where: str) -> int:
    hits: list[int] = []
    for line in table.splitlines():
        if field_substr not in line:
            continue
        m = re.search(r"CRC32C\(\[(?:0\.\.)?(\d+)\)\)", line)
        if not m:
            m = re.search(r"CRC32C\(bytes\[0\.\.(\d+)\)\)", line)
        if m:
            hits.append(int(m.group(1)))
    if len(hits) != 1:
        fail(f"{where}: need exactly 1 CRC coverage on row {field_substr!r}, got {hits}")
    return hits[0]


def safe_relpath(root: pathlib.Path, rel: str, where: str) -> pathlib.Path:
    """Open a repo-relative file with fail-closed symlink/traversal policy.

    Design: every path component under ``root/rel`` is inspected with
    ``lstat`` *before* any ``resolve()`` that would follow symlinks.  Thus a
    frozen document that is itself a symlink to identical bytes (or any
    parent component that is a symlink) is rejected even when content hashes
    would match.  After the unfollowed walk, ``resolve`` + ``commonpath``
    still enforce confinement under the real repo root.
    """
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        fail(f"{where}: absolute path forbidden: {rel!r}")
    if "\\" in rel:
        fail(f"{where}: backslash path forbidden: {rel!r}")
    parts = pathlib.PurePosixPath(rel).parts
    if ".." in parts or any(p in ("", ".") for p in parts):
        fail(f"{where}: path traversal/empty segment forbidden: {rel!r}")

    # Walk raw components without following symlinks.
    # Broken root symlink: exists() may be False — still reject via is_symlink().
    try:
        if root.is_symlink():
            fail(f"{where}: root path is a symlink")
    except OSError as e:
        fail(f"{where}: cannot inspect root: {e}")

    cur = root
    for part in parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            fail(f"{where}: missing path: {rel!r}")
        except OSError as e:
            fail(f"{where}: lstat failed for {rel!r}: {e}")
        if stat_mod.S_ISLNK(st.st_mode):
            fail(f"{where}: symlink forbidden: {rel!r} via {cur}")

    try:
        st_leaf = os.lstat(cur)
    except OSError as e:
        fail(f"{where}: lstat failed for {rel!r}: {e}")
    if not stat_mod.S_ISREG(st_leaf.st_mode):
        fail(f"{where}: not a regular file: {rel!r}")

    # Confinement on the fully resolved real paths (no symlink left to follow
    # on the document path; still blocks unexpected mount/escape cases).
    try:
        root_res = root.resolve(strict=True)
        path_res = cur.resolve(strict=True)
    except (FileNotFoundError, OSError) as e:
        fail(f"{where}: resolve failed for {rel!r}: {e}")
    try:
        common = os.path.commonpath([str(root_res), str(path_res)])
    except ValueError:
        fail(f"{where}: path escapes repo root: {rel!r}")
    if os.path.normcase(common) != os.path.normcase(str(root_res)):
        fail(f"{where}: path escapes repo root: {rel!r}")
    try:
        path_res.relative_to(root_res)
    except ValueError:
        fail(f"{where}: path escapes repo root: {rel!r}")
    return cur


def extract_l6_algorithm_body(u5_text: str, section_marker: str) -> str:
    i = u5_text.find(section_marker)
    if i < 0:
        fail(f"U5 missing section marker {section_marker!r}")
    j = u5_text.find("```text\n", i)
    if j < 0:
        fail("U5 §8.5 missing ```text fence")
    j += len("```text\n")
    k = u5_text.find("\n```", j)
    if k < 0:
        fail("U5 §8.5 unclosed ```text fence")
    return u5_text[j:k]


def load_freeze(paths: Paths) -> dict[str, Any]:
    # Same symlink/traversal policy as frozen documents (component lstat).
    freeze_path = safe_relpath(paths.root, PINNED_FREEZE_RELPATH, "freeze")
    raw = read_bytes(freeze_path)
    digest = sha256_bytes(raw)
    expected_pin = _TEST_PIN_OVERRIDE if _TEST_PIN_OVERRIDE is not None else PINNED_FREEZE_SHA256
    if digest != expected_pin:
        fail(
            f"freeze manifest digest mismatch: got {digest}, "
            f"pinned {expected_pin} "
            f"(docs+manifest co-change without gate pin update is forbidden)"
        )
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        fail(f"freeze manifest JSON invalid: {e}")
    if not isinstance(data, dict):
        fail("freeze manifest root must be object")
    unknown = set(data.keys()) - FREEZE_TOP_KEYS
    if unknown:
        fail(f"freeze unknown top-level keys: {sorted(unknown)}")
    missing = FREEZE_TOP_KEYS - set(data.keys())
    if missing:
        fail(f"freeze missing top-level keys: {sorted(missing)}")
    if data["freeze_id"] != PINNED_FREEZE_ID:
        fail(f"freeze_id {data['freeze_id']!r} != pin {PINNED_FREEZE_ID!r}")
    if str(data["freeze_version"]) != PINNED_FREEZE_VERSION:
        fail(f"freeze_version {data['freeze_version']!r} != pin {PINNED_FREEZE_VERSION!r}")
    if data["hash_algorithm"] != PINNED_HASH_ALGORITHM:
        fail(f"unknown/unsupported hash_algorithm: {data['hash_algorithm']!r}")
    if data.get("schema_version") != 1:
        fail(f"unsupported schema_version: {data.get('schema_version')!r}")
    return data


def check_freeze_documents(paths: Paths, freeze: dict[str, Any]) -> None:
    docs = freeze["documents"]
    if not isinstance(docs, list) or not docs:
        fail("freeze.documents must be non-empty list")
    seen: set[str] = set()
    for i, entry in enumerate(docs):
        if not isinstance(entry, dict):
            fail(f"documents[{i}] must be object")
        ek = set(entry.keys())
        if ek != {"path", "byte_length", "sha256"}:
            fail(f"documents[{i}] keys must be path/byte_length/sha256, got {sorted(ek)}")
        rel = entry["path"]
        if not isinstance(rel, str):
            fail(f"documents[{i}].path must be string")
        if rel in seen:
            fail(f"duplicate document path: {rel}")
        seen.add(rel)
        if not isinstance(entry["byte_length"], int) or entry["byte_length"] < 0:
            fail(f"documents[{i}].byte_length invalid")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            fail(f"documents[{i}].sha256 must be 64 lowercase hex")
        # Fail-closed path safety before allow-list (exercises traversal/symlink checks)
        fpath = safe_relpath(paths.root, rel, f"documents[{i}]")
        if rel not in ALLOWED_DOC_PATHS:
            fail(f"documents[{i}].path not in allowed set: {rel}")
        blob = fpath.read_bytes()
        if len(blob) != entry["byte_length"]:
            fail(
                f"{rel}: byte_length mismatch freeze={entry['byte_length']} disk={len(blob)}"
            )
        got = sha256_bytes(blob)
        if got != entry["sha256"]:
            fail(f"{rel}: sha256 mismatch freeze={entry['sha256']} disk={got}")
    if seen != ALLOWED_DOC_PATHS:
        fail(f"documents set mismatch: got {sorted(seen)} expected {sorted(ALLOWED_DOC_PATHS)}")


def check_l6_algorithm_pin(paths: Paths, freeze: dict[str, Any]) -> None:
    alg = freeze["l6_algorithm"]
    if not isinstance(alg, dict):
        fail("l6_algorithm must be object")
    unknown = set(alg.keys()) - L6_ALG_KEYS
    if unknown:
        fail(f"l6_algorithm unknown keys: {sorted(unknown)}")
    missing = L6_ALG_KEYS - set(alg.keys())
    if missing:
        fail(f"l6_algorithm missing keys: {sorted(missing)}")
    if alg["source_path"] != "docs/25-u5-cell-operating-assignment.md":
        fail(f"l6_algorithm.source_path unexpected: {alg['source_path']!r}")
    if alg["fence_language"] != "text":
        fail("l6_algorithm.fence_language must be text")
    body = alg["body"]
    if not isinstance(body, str) or not body:
        fail("l6_algorithm.body must be non-empty string")
    body_b = body.encode("utf-8")
    if len(body_b) != alg["body_byte_length"]:
        fail("l6_algorithm.body_byte_length mismatch")
    if sha256_bytes(body_b) != alg["body_sha256"]:
        fail("l6_algorithm.body_sha256 mismatch vs body field")
    if not re.fullmatch(r"[0-9a-f]{64}", alg["body_sha256"]):
        fail("l6_algorithm.body_sha256 format")

    phases = alg["ordered_phases"]
    if phases != ["L6a", "L6b", "L6c", "L6d"]:
        fail(f"l6 ordered_phases must be L6a..L6d exact, got {phases!r}")

    decls = alg["declarations"]
    if decls != {
        "L6_ORDER": "FENCE_BEFORE_COMMIT",
        "DEFERRED_FENCE_FORBIDDEN": "1",
    }:
        fail(f"l6 declarations mismatch: {decls!r}")

    cons = alg["constraints"]
    expected_cons = {
        "FENCE_STEP": "L6b",
        "COMMIT_STEP": "L6d",
        "FENCE_BEFORE_COMMIT": "1",
        "SAME_OWNER_SYNC": "1",
        "DEFERRED_AFTER_COMMIT_OR_PERSIST_FORBIDDEN": "1",
    }
    if cons != expected_cons:
        fail(f"l6 constraints mismatch: {cons!r}")

    # Exact fence extraction from live U5 must match freeze body bit-exact
    u5 = read_text(paths.u5)
    live = extract_l6_algorithm_body(u5, alg["section_marker"])
    if live != body:
        fail(
            "U5 §8.5 algorithm fence body != freeze l6_algorithm.body "
            "(free prose outside fence is not order authority; fence itself is pinned)"
        )
    # Structural markers inside pinned body
    require_contains(body, "L6_ORDER=FENCE_BEFORE_COMMIT; DEFERRED_FENCE_FORBIDDEN=1", "L6 order decl")
    require_contains(
        body,
        "L6_CONSTRAINT: FENCE_STEP=L6b; COMMIT_STEP=L6d; FENCE_BEFORE_COMMIT=1; SAME_OWNER_SYNC=1",
        "L6 constraint fence/commit",
    )
    require_contains(
        body,
        "L6_CONSTRAINT: DEFERRED_AFTER_COMMIT_OR_PERSIST_FORBIDDEN=1",
        "L6 constraint deferred",
    )
    if body.find("L6b **permit_fence_before_commit:**") > body.find("L6d commit(FULL)"):
        fail("pinned L6 body: fence after commit")
    for phase in ("L6a", "L6b", "L6c", "L6d"):
        if phase not in body:
            fail(f"pinned L6 body missing phase {phase}")

    # Authority prose (outside fence) — not NLP; exact required strings from freeze
    for s in freeze["authority_prose_required_in_u5"]:
        require_contains(u5, s, "U5 authority prose")


def check_no_contradictory_nct1_crc_prose(doc: str, authoritative: int) -> None:
    other = ("NCP1", "NCS1", "NCH1", "NCD1", "NCT0", "ARW1", "OFFER", "ASSIGNMENT")
    for m in re.finditer(r"CRC32C\(\[(?:0\.\.)?(\d+)\)\)", doc):
        n = int(m.group(1))
        a = max(0, m.start() - 160)
        b = min(len(doc), m.end() + 80)
        window = doc[a:b]
        if "payload_crc" in window:
            continue
        if any(tok in window for tok in other) and "### 11.2 NCT1" not in window:
            if not re.search(r"NCT1.{0,40}header_crc|header_crc32c.{0,40}NCT1", window):
                continue
        if "NCT1" not in window and "### 11.2" not in window:
            continue
        if n != authoritative:
            fail(
                f"contradictory NCT1 header CRC: found coverage {n}, "
                f"authoritative table {authoritative}"
            )


def check_u5_layouts(paths: Paths) -> None:
    t = read_text(paths.u5)
    require_contains(t, "# 25. U5:", "U5 title")
    require_contains(t, "selected_control_version == 2", "U5 ==2")
    require_absent(t, "selected_control_version >= 2", "U5 no >=2")

    setb = section_between(t, "### 6.2 `ASSIGNMENT_SET`", "### 6.3 `ASSIGNMENT_ACK`", "SET")
    check_layout([r for r in parse_ose_rows(first_text_fence(setb, "SET")) if r[2] <= 148], "SET", 148)
    ack = section_between(t, "### 6.3 `ASSIGNMENT_ACK`", "### 6.4 `ASSIGNMENT_REJECT`", "ACK")
    check_layout(parse_ose_rows(first_text_fence(ack, "ACK")), "ACK", 64)
    rej = section_between(t, "### 6.4 `ASSIGNMENT_REJECT`", "### 6.5 `reject_code`", "REJECT")
    check_layout(parse_ose_rows(first_text_fence(rej, "REJECT")), "REJECT", 76)

    arw_k = section_between(t, "**Key**（exact **36** bytes）", "**Value**（exact **172** bytes", "ARW key")
    check_layout(parse_ose_rows(first_text_fence(arw_k, "ARW key")), "ARW key", 36)
    arw_v = section_between(t, "**Value**（exact **172** bytes", "算術:", "ARW value")
    check_layout(parse_ose_rows(first_text_fence(arw_v, "ARW value")), "ARW value", 172)

    require_contains(t, "ninlil.ctl.v1", "ns")
    a5 = read_text(paths.adr5)
    require_contains(a5, "selected_control_version == 2", "ADR5")
    require_absent(a5, "control_version ≥ 2", "ADR5 ge2")
    require_absent(a5, "control_version >= 2", "ADR5 ge2a")


def check_u6_layouts(paths: Paths) -> None:
    t = read_text(paths.u6)
    require_contains(t, "# 26. U6:", "title")
    ksec = section_between(t, "### 11.1 Canonical key table", "### 11.2 NCT1 value", "keys")
    require_contains(ksec, "| `ARW1` | **36** |", "ARW36")
    require_contains(ksec, "recipient_device_id", "recip")
    require_contains(ksec, "| `NCT1` | **20** |", "NCT20")

    offer = section_between(t, "### 6.2 `CUSTODY_OFFER`", "### 6.3 `CUSTODY_ACCEPT`", "OFFER")
    check_layout([r for r in parse_ose_rows(first_text_fence(offer, "OFFER")) if r[2] <= 72], "OFFER", 72)

    for title, a, b, end in [
        ("ACCEPT", "### 6.3 `CUSTODY_ACCEPT`", "### 6.4 `CUSTODY_REJECT`", 56),
        ("REJECT", "### 6.4 `CUSTODY_REJECT`", "### 6.5 `CUSTODY_BUSY`", 60),
        ("BUSY", "### 6.5 `CUSTODY_BUSY`", "### 6.6 `reject_code`", 64),
    ]:
        sec = section_between(t, a, b, title)
        fence = first_text_fence(sec, title)
        rows = parse_ose_rows(fence)
        if not rows:
            rows = []
            for line in fence.splitlines():
                m = re.match(r"^(\d+)\s+(\d+)\s+(\S+)", line.strip())
                if m:
                    o, s = int(m.group(1)), int(m.group(2))
                    rows.append((o, s, o + s, m.group(3)))
        check_layout(rows, title, end)

    nct1 = section_between(t, "### 11.2 NCT1 value", "### 11.3 NCP1 value", "NCT1")
    nct1_tbl = first_text_fence(nct1, "NCT1")
    check_layout([r for r in parse_ose_rows(nct1_tbl) if r[2] <= 92], "NCT1", 92)
    cov = crc_from_table_row(nct1_tbl, "header_crc32c", "NCT1")
    if cov != 88:
        fail(f"NCT1 table CRC coverage {cov} != 88")
    check_no_contradictory_nct1_crc_prose(t, 88)

    ncp1 = section_between(t, "### 11.3 NCP1 value", "### 11.4 NCS1 value", "NCP1")
    ncp1_tbl = first_text_fence(ncp1, "NCP1")
    check_layout([r for r in parse_ose_rows(ncp1_tbl) if r[2] <= 120], "NCP1 hdr", 120)
    require_contains(ncp1_tbl, "payload_present", "payload_present field")
    require_contains(
        ncp1_tbl, "content_digest          original offer bind; IMMUTABLE", "immutable digest"
    )
    require_contains(ncp1, "format_version          u32 BE = **2**", "NCP1 v2")
    require_contains(ncp1, "payload_present==0", "present0 rule")
    require_contains(ncp1, "empty digest に書き換え禁止", "no empty digest rewrite")
    cov_ncp = crc_from_table_row(ncp1_tbl, "header_crc32c", "NCP1")
    if cov_ncp != 116:
        fail(f"NCP1 CRC coverage {cov_ncp} != 116")
    require_contains(ncp1_tbl, "retention_anchor_mono_ms", "NCP1 retention anchor")
    require_contains(ncp1_tbl, "retention_anchor_clock_epoch_id", "NCP1 retention epoch")

    ncs1 = section_between(t, "### 11.4 NCS1 value", "### 11.5 NCH1 value", "NCS1")
    check_layout(parse_ose_rows(first_text_fence(ncs1, "NCS1")), "NCS1", 92)

    nch1 = section_between(t, "### 11.5 NCH1 value", "### 11.5.1 Handoff", "NCH1")
    check_layout(parse_ose_rows(first_text_fence(nch1, "NCH1")), "NCH1", 88)

    ncd1 = section_between(t, "### 11.5.2 Explicit discard", "### 11.5.3 discard_reason", "NCD1")
    ncd1_tbl = first_text_fence(ncd1, "NCD1")
    check_layout(parse_ose_rows(ncd1_tbl), "NCD1", 108)
    if crc_from_table_row(ncd1_tbl, "crc32c", "NCD1") != 104:
        fail("NCD1 CRC must be 104")
    require_contains(ncd1, "二択禁止", "canonical discard")
    require_contains(ncd1_tbl, "retention_anchor_mono_ms", "NCD1 anchor")
    require_absent(ncd1, "payload empty allowed", "no empty alt")

    nct0 = section_between(t, "#### 11.11.1 NCT0 exact layout", "#### 11.11.2 terminal_class", "NCT0")
    nct0_tbl = first_text_fence(nct0, "NCT0")
    check_layout(parse_ose_rows(nct0_tbl), "NCT0", 88)
    if crc_from_table_row(nct0_tbl, "crc32c", "NCT0") != 84:
        fail("NCT0 CRC must be 84")
    require_contains(nct0_tbl, "retention_anchor_mono_ms", "NCT0 anchor")

    require_contains(t, "G_EVIDENCE", "G_EVIDENCE")
    require_contains(t, "G_TERMINAL:", "G_TERMINAL")
    require_contains(
        t, "payload_present = 0  # payload_bytes 除去; digest/length IMMUTABLE", "REL_IMMEDIATE present0"
    )
    require_contains(t, "#### 11.11.4 Retention elapsed", "retention elapsed")
    require_contains(t, "SAFE_HOLD", "SAFE_HOLD")

    rel_pol = section_between(t, "### 10.3 Release policy", "### 10.4", "10.3")
    require_contains(rel_pol, "自動 GC **禁止**", "10.3 HOLD ban phrase")
    require_contains(rel_pol, "GC permission にはしない", "10.3 anchor not GC permission")
    require_contains(rel_pol, "BUSY / CAPACITY / fence", "10.3 HOLD backpressure")
    if not re.search(r"`REL_HOLD`\s*\(2\).{0,160}\|\s*\*\*no\*\*", rel_pol, re.S):
        fail("10.3 REL_HOLD auto timer GC column must be **no**")
    if "RELEASE_HOLD after policy" in t:
        fail("eligibility must not list RELEASE_HOLD as timer class via after policy")

    elig = section_between(
        t,
        "**eligibility クラス（閉じた表）:**",
        "**auto timer GC eligibility AND",
        "eligibility",
    )
    hold_rows = [
        ln
        for ln in elig.splitlines()
        if "NCP_RELEASE_HOLD" in ln or ("REL_HOLD" in ln and ln.strip().startswith("| NCP"))
    ]
    if len(hold_rows) != 1:
        fail(f"eligibility must have exactly 1 NCP_RELEASE_HOLD row, got {len(hold_rows)}")
    hold_cells = [c.strip() for c in hold_rows[0].strip().strip("|").split("|")]
    if len(hold_cells) < 2:
        fail(f"HOLD eligibility row malformed: {hold_rows[0]!r}")
    auto_cell = hold_cells[1]
    if not auto_cell.startswith("**no**"):
        fail(
            "NCP_RELEASE_HOLD eligibility auto timer GC cell must start with **no**, "
            f"got {auto_cell!r}"
        )
    if re.search(r"\*\*yes\*\*|60\s*s|60000|timer", auto_cell, re.I):
        fail(f"NCP_RELEASE_HOLD auto timer GC cell must not allow timer: {auto_cell!r}")
    require_contains(t, "**auto timer GC eligibility AND（REL_HOLD を含めない）:**", "AND exclude HOLD")

    boot_s = section_between(t, "### 12.2 Sender reconstruction", "### 12.3", "boot sender")
    require_contains(
        boot_s, "NCP_RELEASE_HOLD → no re-OFFER; **auto GC 不可**", "boot HOLD no auto GC"
    )
    require_contains(t, "NCP_RELEASE_HOLD | no re-OFFER; hold until explicit release FULL", "12.4 HOLD")

    require_contains(t, "custody_payload_release", "payload release counter name")
    require_contains(t, "### 14.1 `custody_payload_release`", "§14.1 table")
    require_contains(t, "closed increment table", "§14.1 closed")
    require_contains(t, "NCP_RELEASE_HOLD 滞在中", "counter never on HOLD")
    require_contains(t, "sender `G_EVIDENCE` REL_IMMEDIATE", "counter sender REL_IMMEDIATE")
    require_contains(t, "sender `REL_AFTER_RETENTION` timer GC", "counter AFTER_RETENTION")
    require_contains(t, "sender `G_RELEASE_HOLD_END`", "counter HOLD explicit end")
    require_contains(t, "receiver handoff FULL OK", "counter receiver handoff")
    require_contains(t, "receiver explicit discard FULL OK", "counter receiver discard")
    require_contains(t, "public ABI 非露出", "private stats scope")
    require_contains(t, "旧称 `custody_release`（handoff/discard only）は **廃止**", "old name retired")
    for m in re.finditer(r"handoff/discard only", t):
        ctx = t[max(0, m.start() - 40) : m.end() + 40]
        if re.search(r"廃止|旧称|MUST\s*NOT|禁止", ctx):
            continue
        fail("affirmative handoff/discard-only counter scope prose")
    if re.search(r"### 14\.1 `custody_release`", t):
        fail("§14.1 must be custody_payload_release, not custody_release")

    require_contains(t, "epoch mismatch", "epoch mismatch")
    boot = section_between(t, "### 12.1 Receiver reconstruction", "### 12.2 Sender", "boot")
    require_contains(boot, "NCD1", "boot NCD1")
    require_contains(boot, "NCT0", "boot NCT0")
    require_contains(t, "### 12.3 COMMIT_UNKNOWN recovery matrix", "matrix")
    require_contains(t, "u64 への切詰め", "no u64 trunc")
    require_contains(t, "sender_deadline_mono_ms` field は **存在しない**", "no deadline")
    if t.find("### 10.4") > t.find("### 10.5"):
        fail("10.4 after 10.5")

    a6 = read_text(paths.adr6)
    require_contains(a6, "selected_control_version == 2", "ADR6")
    require_absent(a6, "control_version ≥ 2", "ADR6 ge2")
    require_absent(a6, "control_version >= 2", "ADR6 ge2a")


def check_cross(paths: Paths) -> None:
    require_contains(read_text(paths.doc05), "permit_bind_generation", "05")
    require_contains(read_text(paths.doc23), "permit_bind_generation", "23")
    require_contains(read_text(paths.doc07), "u5_u6_docs_gate", "07")
    require_contains(
        read_text(paths.doc07),
        "immutability",
        "07 immutability wording",
    )
    for label, path in (
        ("u5", paths.u5),
        ("u6", paths.u6),
        ("adr5", paths.adr5),
        ("adr6", paths.adr6),
    ):
        text = read_text(path)
        if "selected_control_version >= 2" in text or "control_version ≥ 2" in text:
            fail(f"{label} >=2")


def run_check(paths: Paths | None = None) -> None:
    paths = paths or P
    freeze = load_freeze(paths)
    check_freeze_documents(paths, freeze)
    check_l6_algorithm_pin(paths, freeze)
    check_u5_layouts(paths)
    check_u6_layouts(paths)
    check_cross(paths)
    print(
        "u5_u6_docs_gate ok: "
        f"freeze={PINNED_FREEZE_ID}@v{PINNED_FREEZE_VERSION} "
        "bytes_pin+l6_algorithm_pin "
        "layouts REL_HOLD counter "
        "(immutability/freshness — not NLP semantic proof)"
    )


def _unlink_path(path: pathlib.Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists() and path.is_dir():
        shutil.rmtree(path)


def _copy_tree(dst: pathlib.Path) -> None:
    """Populate a *fresh* destination tree from REPO_ROOT.

    Callers must pass an empty directory (prefer a new TemporaryDirectory per
    case). This function does not attempt to repair leftover symlink renames.
    """
    for rel in [
        "docs/25-u5-cell-operating-assignment.md",
        "docs/26-u6-transport-custody.md",
        "docs/adr/0005-u5-cell-operating-assignment-control-v2.md",
        "docs/adr/0006-u6-transport-custody.md",
        "docs/05-security-and-compliance.md",
        "docs/07-testing-and-quality.md",
        "docs/23-usb-radio-boundary.md",
        PINNED_FREEZE_RELPATH,
    ]:
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists() or out.is_symlink():
            _unlink_path(out)
        shutil.copy2(REPO_ROOT / rel, out)


def _fresh_tree() -> tuple[tempfile.TemporaryDirectory[str], Paths]:
    """Independent temp root per case (no cross-case symlink residue)."""
    td = tempfile.TemporaryDirectory()
    root = pathlib.Path(td.name)
    _copy_tree(root)
    return td, Paths(root)


def _expect_fail(label: str, paths: Paths, mut: Callable[[Paths], None]) -> None:
    mut(paths)
    try:
        run_check(paths)
    except GateFailure as e:
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail (false green)")


def _expect_fail_reason(
    label: str, paths: Paths, mut: Callable[[Paths], None], expect: str
) -> None:
    mut(paths)
    try:
        run_check(paths)
    except GateFailure as e:
        msg = str(e)
        if expect not in msg:
            fail(
                f"self-test {label!r} failed for wrong reason: "
                f"expected {expect!r} in {msg!r}"
            )
        # Reject accidental freeze-path false positives for document cases.
        if "documents[0]" in expect and msg.startswith("freeze:"):
            fail(f"self-test {label!r} hit freeze path instead of document: {msg!r}")
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail (false green)")


def _rewrite_freeze(paths: Paths, mutator: Callable[[dict[str, Any]], None]) -> None:
    data = json.loads(paths.freeze.read_text(encoding="utf-8"))
    mutator(data)
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    paths.freeze.write_text(text, encoding="utf-8")


def _rehash_docs_into_freeze(paths: Paths) -> None:
    data = json.loads(paths.freeze.read_text(encoding="utf-8"))
    for entry in data["documents"]:
        blob = (paths.root / entry["path"]).read_bytes()
        entry["byte_length"] = len(blob)
        entry["sha256"] = sha256_bytes(blob)
    # refresh l6 body from U5 if present
    u5 = (paths.root / "docs/25-u5-cell-operating-assignment.md").read_text(encoding="utf-8")
    try:
        body = extract_l6_algorithm_body(u5, data["l6_algorithm"]["section_marker"])
        bb = body.encode("utf-8")
        data["l6_algorithm"]["body"] = body
        data["l6_algorithm"]["body_byte_length"] = len(bb)
        data["l6_algorithm"]["body_sha256"] = sha256_bytes(bb)
    except GateFailure:
        pass
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    paths.freeze.write_text(text, encoding="utf-8")


def run_self_test() -> None:
    danger_lines = [
        "The old permit may be deactivated once persistence succeeds by a worker.",
        "The prior authorization may be cancelled after data is durably stored by a background task.",
        "The legacy generation may be retired following commit by a worker.",
        "The old permit may expire upon commit in a background task.",
        "The old permit may be deactivated after the write completes by a worker.",
        "At transaction completion, a background worker may deactivate the old permit.",
        "The old permit may be deactivated after persistence completes by a scheduled job.",
        "旧許可は書き込みが終了してからバックグラウンドジョブで解除可能。",
        "旧許可は保存完了後にジョブで解除可能。",
        "The old permit is not possible to deactivate after persistence completes by a worker.",
        "The old permit may be deactivated after persistence completes by a background worker.",
        "L6bの旧generation阻止はL6d完了後の非同期workerに任せてよい。",
        "前認可の失効は書込後にタスクで実行可能である。",
    ]

    def mut_append(path_attr: str, text: str) -> Callable[[Paths], None]:
        def _m(p: Paths) -> None:
            f = getattr(p, path_attr)
            f.write_bytes(f.read_bytes() + text.encode("utf-8"))

        return _m

    def mut_byte(path_attr: str, pos: str) -> Callable[[Paths], None]:
        def _m(p: Paths) -> None:
            f = getattr(p, path_attr)
            b = bytearray(f.read_bytes())
            if not b:
                fail("empty file for byte mut")
            if pos == "start":
                b[0] = (b[0] + 1) % 256
            elif pos == "mid":
                i = len(b) // 2
                b[i] = (b[i] + 1) % 256
            elif pos == "end":
                b[-1] = (b[-1] + 1) % 256
            elif pos == "append":
                b.append(0x0A)
            elif pos == "delete":
                del b[-1]
            else:
                fail(f"bad pos {pos}")
            f.write_bytes(bytes(b))

        return _m

    mutations: list[tuple[str, Callable[[Paths], None]]] = []

    # 1-byte / add / delete for each frozen doc
    for attr, name in (
        ("u5", "u5"),
        ("u6", "u6"),
        ("adr5", "adr5"),
        ("adr6", "adr6"),
    ):
        for pos in ("start", "mid", "end", "append", "delete"):
            mutations.append((f"{name}_byte_{pos}", mut_byte(attr, pos)))

    # danger prose append without freeze update (any 1-byte+ change fails pin)
    for i, line in enumerate(danger_lines):
        mutations.append((f"danger_append_{i}", mut_append("u5", "\n\n" + line + "\n")))

    # doc+manifest co-update without gate pin update
    def mut_doc_and_manifest(p: Paths) -> None:
        p.u5.write_bytes(p.u5.read_bytes() + b"\n# unpinned change\n")
        _rehash_docs_into_freeze(p)

    mutations.append(("doc_and_manifest_without_gate_pin", mut_doc_and_manifest))

    # freeze structural fails
    def mut_freeze_path_traversal(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["documents"][0]["path"] = "../etc/passwd"

        _rewrite_freeze(p, m)

    def mut_freeze_duplicate(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["documents"].append(dict(d["documents"][0]))

        _rewrite_freeze(p, m)

    def mut_freeze_missing_doc(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["documents"] = d["documents"][:3]

        _rewrite_freeze(p, m)

    def mut_freeze_unknown_algo(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["hash_algorithm"] = "SHA-1"

        _rewrite_freeze(p, m)

    def mut_freeze_unknown_key(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["extra_authority"] = True

        _rewrite_freeze(p, m)

    def mut_freeze_phase_swap(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["l6_algorithm"]["ordered_phases"] = ["L6a", "L6c", "L6b", "L6d"]

        _rewrite_freeze(p, m)

    def mut_freeze_constraint_flip(p: Paths) -> None:
        def m(d: dict[str, Any]) -> None:
            d["l6_algorithm"]["constraints"]["FENCE_BEFORE_COMMIT"] = "0"
            d["l6_algorithm"]["declarations"]["DEFERRED_FENCE_FORBIDDEN"] = "0"

        _rewrite_freeze(p, m)

    def mut_l6_swap_in_doc_only(p: Paths) -> None:
        t = p.u5.read_text(encoding="utf-8")
        old = (
            "      L6b **permit_fence_before_commit:** outstanding Physical Compliance Permit を\n"
            "          generation < new で revoke/fence（in-memory registry clear; durable generation は ARW に bind;\n"
            "          旧 generation の consume 拒否）\n"
            "      L6c put ARW key（36B canonical）\n"
            "      L6d commit(FULL)"
        )
        new = (
            "      L6c put ARW key（36B canonical）\n"
            "      L6d commit(FULL)\n"
            "      L6b **permit_fence_before_commit:** outstanding Physical Compliance Permit を\n"
            "          generation < new で revoke/fence（in-memory registry clear; durable generation は ARW に bind;\n"
            "          旧 generation の consume 拒否）"
        )
        t2 = t.replace(old, new, 1)
        if t2 == t:
            fail("self-test setup: L6 steps not found")
        p.u5.write_text(t2, encoding="utf-8")

    def mut_rel_hold_auto_gc(p: Paths) -> None:
        t = p.u6.read_text(encoding="utf-8")
        target = (
            "| NCP `NCP_RELEASE_HOLD`（REL_HOLD） | **no**（anchor あっても **no**） "
            "| **yes** — `G_RELEASE_HOLD_END` または explicit discard 相当 FULL |"
        )
        spoof = (
            "| NCP `NCP_RELEASE_HOLD`（REL_HOLD） | **yes**（60s timer） "
            "| **yes** — timer or explicit |"
        )
        t2 = t.replace(target, spoof, 1)
        if t2 == t:
            fail("self-test setup: REL_HOLD row missing")
        p.u6.write_text(t2, encoding="utf-8")

    def mut_counter_handoff_only(p: Paths) -> None:
        t = p.u6.read_text(encoding="utf-8")
        t2 = t.replace(
            "### 14.1 `custody_payload_release` closed increment table",
            "### 14.1 `custody_release` handoff/discard only",
            1,
        )
        if t2 == t:
            fail("self-test setup: §14.1 missing")
        p.u6.write_text(t2 + "\n\ncustody_release increments on handoff/discard only.\n", encoding="utf-8")

    def mut_ncp_drop_payload_present(p: Paths) -> None:
        t = p.u6.read_text(encoding="utf-8")
        ncp = section_between(t, "### 11.3 NCP1 value", "### 11.4 NCS1 value", "ncp")
        fence = first_text_fence(ncp, "ncp")
        bad = fence.replace("payload_present         u8 exact 0 or 1\n", "")
        p.u6.write_text(t.replace(fence, bad, 1), encoding="utf-8")

    def mut_arw20(p: Paths) -> None:
        t = p.u6.read_text(encoding="utf-8")
        p.u6.write_text(t.replace("| `ARW1` | **36** |", "| `ARW1` | **20** |", 1), encoding="utf-8")

    def mut_adr6_ge2(p: Paths) -> None:
        t = p.adr6.read_text(encoding="utf-8")
        p.adr6.write_text(
            t.replace("selected_control_version == 2", "control_version ≥ 2", 1),
            encoding="utf-8",
        )

    mutations.extend(
        [
            # Production pin-first: any freeze rewrite fails digest (dead if only these exist)
            ("freeze_path_traversal_pin_first", mut_freeze_path_traversal),
            ("freeze_duplicate_path_pin_first", mut_freeze_duplicate),
            ("freeze_missing_doc_pin_first", mut_freeze_missing_doc),
            ("freeze_unknown_algorithm_pin_first", mut_freeze_unknown_algo),
            ("freeze_unknown_key_pin_first", mut_freeze_unknown_key),
            ("freeze_phase_swap_pin_first", mut_freeze_phase_swap),
            ("freeze_constraint_flip_pin_first", mut_freeze_constraint_flip),
            ("u5_l6_fence_after_commit_order", mut_l6_swap_in_doc_only),
            ("u6_rel_hold_auto_gc", mut_rel_hold_auto_gc),
            ("u6_counter_handoff_only", mut_counter_handoff_only),
            ("u6_ncp_drop_payload_present", mut_ncp_drop_payload_present),
            ("u6_arw_key_20", mut_arw20),
            ("adr6_ge2", mut_adr6_ge2),
        ]
    )

    def deep_path_traversal(d: dict[str, Any]) -> None:
        d["documents"][0]["path"] = "../etc/passwd"

    def deep_duplicate(d: dict[str, Any]) -> None:
        d["documents"].append(dict(d["documents"][0]))

    def deep_missing(d: dict[str, Any]) -> None:
        d["documents"] = d["documents"][:3]

    def deep_unknown_algo(d: dict[str, Any]) -> None:
        d["hash_algorithm"] = "SHA-1"

    def deep_unknown_key(d: dict[str, Any]) -> None:
        d["extra_authority"] = True

    def deep_phase_swap(d: dict[str, Any]) -> None:
        d["l6_algorithm"]["ordered_phases"] = ["L6a", "L6c", "L6b", "L6d"]

    def deep_constraint_flip(d: dict[str, Any]) -> None:
        d["l6_algorithm"]["constraints"]["FENCE_BEFORE_COMMIT"] = "0"

    # Deep freeze content validation with temporary pin bypass (test helper only).
    deep: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
        ("deep_path_traversal", deep_path_traversal, "path traversal"),
        ("deep_duplicate_path", deep_duplicate, "duplicate document path"),
        ("deep_missing_doc", deep_missing, "documents set mismatch"),
        ("deep_unknown_algorithm", deep_unknown_algo, "unknown/unsupported hash_algorithm"),
        ("deep_unknown_key", deep_unknown_key, "unknown top-level keys"),
        ("deep_phase_swap", deep_phase_swap, "ordered_phases must be L6a..L6d"),
        ("deep_constraint_flip", deep_constraint_flip, "l6 constraints mismatch"),
    ]

    global _TEST_PIN_OVERRIDE

    # --- pristine: isolated tree ---
    td, p = _fresh_tree()
    try:
        run_check(p)
        print("  self-test pristine tree correctly passed")
    finally:
        td.cleanup()

    # --- pin-first / structural mutations: one fresh tree each ---
    for label, mut in mutations:
        td, p = _fresh_tree()
        try:
            _expect_fail(label, p, mut)
        finally:
            td.cleanup()

    # --- deep content failures with pin bypass: isolated tree each ---
    for label, mutator, expect in deep:
        td, p = _fresh_tree()
        try:
            _rewrite_freeze(p, mutator)
            _TEST_PIN_OVERRIDE = sha256_file(p.freeze)
            try:
                run_check(p)
                fail(f"self-test deep {label!r} did not fail (false green)")
            except GateFailure as e:
                if expect not in str(e):
                    fail(
                        f"self-test deep {label!r} failed for wrong reason: "
                        f"expected {expect!r} in {e!r}"
                    )
                print(f"  self-test deep {label!r} correctly failed: {e}")
            finally:
                _TEST_PIN_OVERRIDE = None
        finally:
            td.cleanup()

    def _run_symlink_case(
        label: str,
        setup: Callable[[Paths], None],
        expect_substrings: list[str],
        assert_after_setup: Callable[[Paths], None],
    ) -> None:
        td, p = _fresh_tree()
        try:
            try:
                setup(p)
            except OSError as e:
                print(f"  self-test {label!r} skipped (OS): {e}")
                return
            assert_after_setup(p)
            try:
                run_check(p)
                fail(f"self-test {label!r} did not fail (false green)")
            except GateFailure as e:
                msg = str(e)
                for exp in expect_substrings:
                    if exp not in msg:
                        fail(
                            f"self-test {label!r} failed for wrong reason: "
                            f"expected {exp!r} in {msg!r}"
                        )
                if msg.startswith("freeze:") and any(
                    s.startswith("documents[0]") for s in expect_substrings
                ):
                    fail(
                        f"self-test {label!r} false-positive on freeze path: {msg!r}"
                    )
                print(f"  self-test mutation {label!r} correctly failed: {e}")
        finally:
            td.cleanup()

    # freeze leaf symlink
    def setup_freeze_symlink(p: Paths) -> None:
        fr = p.freeze
        tmp = p.root / "spec" / "frozen" / "_real.json"
        tmp.write_bytes(fr.read_bytes())
        fr.unlink()
        os.symlink(tmp.name, fr)

    def assert_freeze_symlink(p: Paths) -> None:
        if not p.freeze.is_symlink():
            fail("self-test setup: freeze is not a symlink after setup")

    _run_symlink_case(
        "freeze_symlink",
        setup_freeze_symlink,
        ["freeze:", "symlink forbidden", PINNED_FREEZE_RELPATH],
        assert_freeze_symlink,
    )

    # docs/25 leaf → same-bytes regular file
    def setup_u5_symlink_same_bytes(p: Paths) -> None:
        real = p.u5.with_name(p.u5.name + ".real")
        real.write_bytes(p.u5.read_bytes())
        p.u5.unlink()
        os.symlink(real.name, p.u5)

    def assert_u5_leaf_symlink(p: Paths) -> None:
        if not p.u5.is_symlink():
            fail("self-test setup: u5 path is not a leaf symlink after setup")
        # freeze must remain a regular file so failure is documents[0], not freeze
        if p.freeze.is_symlink():
            fail("self-test setup contamination: freeze became symlink")

    _run_symlink_case(
        "u5_doc_symlink_same_bytes",
        setup_u5_symlink_same_bytes,
        [
            "documents[0]:",
            "symlink forbidden",
            "docs/25-u5-cell-operating-assignment.md",
        ],
        assert_u5_leaf_symlink,
    )

    # parent docs/ is a symlink
    def setup_u5_parent_dir_symlink(p: Paths) -> None:
        docs = p.root / "docs"
        docs_real = p.root / "docs_real"
        docs.rename(docs_real)
        os.symlink("docs_real", docs)

    def assert_docs_parent_symlink(p: Paths) -> None:
        docs = p.root / "docs"
        if not docs.is_symlink():
            fail("self-test setup: docs/ is not a symlink after setup")
        if p.freeze.is_symlink():
            fail("self-test setup contamination: freeze became symlink")

    # parent: failure must be documents[0] at the docs/ component (not freeze, not leaf file)
    td, p = _fresh_tree()
    try:
        try:
            setup_u5_parent_dir_symlink(p)
        except OSError as e:
            print(f"  self-test 'u5_parent_dir_symlink' skipped (OS): {e}")
        else:
            assert_docs_parent_symlink(p)
            try:
                run_check(p)
                fail("self-test 'u5_parent_dir_symlink' did not fail (false green)")
            except GateFailure as e:
                msg = str(e)
                for exp in (
                    "documents[0]:",
                    "symlink forbidden",
                    "docs/25-u5-cell-operating-assignment.md",
                ):
                    if exp not in msg:
                        fail(
                            f"self-test 'u5_parent_dir_symlink' wrong reason: "
                            f"expected {exp!r} in {msg!r}"
                        )
                if msg.startswith("freeze:"):
                    fail(
                        f"self-test 'u5_parent_dir_symlink' false-positive on freeze: {msg!r}"
                    )
                # via path must be the docs parent component, not the leaf .md
                if not re.search(r"via .+/docs$", msg):
                    fail(
                        f"self-test 'u5_parent_dir_symlink' expected via .../docs, got {msg!r}"
                    )
                print(f"  self-test mutation 'u5_parent_dir_symlink' correctly failed: {e}")
    finally:
        td.cleanup()

    # broken leaf symlink
    def setup_u5_broken_symlink(p: Paths) -> None:
        p.u5.unlink()
        os.symlink("nonexistent-u5-target-xyz", p.u5)

    _run_symlink_case(
        "u5_broken_symlink",
        setup_u5_broken_symlink,
        [
            "documents[0]:",
            "symlink forbidden",
            "docs/25-u5-cell-operating-assignment.md",
        ],
        assert_u5_leaf_symlink,
    )

    print(
        f"u5_u6_docs_gate self-test ok: pristine PASS + {len(mutations)} "
        f"fail mutations + {len(deep)} deep pin-bypass content fails "
        f"(+ isolated symlink cases when available); immutability pin (not NLP)"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print("usage: u5_u6_docs_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            run_check()
            return 0
        run_self_test()
        return 0
    except GateFailure as e:
        print(f"u5_u6_docs_gate FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
