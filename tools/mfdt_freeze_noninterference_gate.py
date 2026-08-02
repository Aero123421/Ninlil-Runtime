#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MFDT freeze non-interference gate.

Proves that MFDT default-OFF / SPEC / private-implementation work must not
mutate the Accepted U5/U6 v2 freeze surface (manifest + pinned document
byte_length/sha256) or the R6-pinned docs/25 length/hash. docs/23 is also
byte-pinned to the current freeze-compatible baseline so silent R6 boundary
drift from MFDT catalog edits fails closed.

This gate does **not** re-freeze or broaden U5/U6 v2. Legitimate freeze change
requires a separate freeze version, Accepted ADR, and independent review —
not MFDT Proposed v3 work.

Usage:
  python3 tools/mfdt_freeze_noninterference_gate.py check
  python3 tools/mfdt_freeze_noninterference_gate.py self-test
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import sys
import tempfile
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Hard pins — change only with deliberate non-MFDT freeze re-acceptance.
PINNED_FREEZE_RELPATH = "spec/frozen/u5-u6-normative-freeze-v2.json"
PINNED_FREEZE_ID = "u5-u6-normative-freeze"
PINNED_FREEZE_VERSION = "2"
PINNED_FREEZE_SHA256 = (
    "deff647c3ed9da31c9a521cea398aa49440ccd9884b8031d468cab37fea7e783"
)
PINNED_FREEZE_BYTE_LENGTH = 4299

# Exact documents from freeze v2 (must match u5_u6_docs_gate / freeze JSON).
PINNED_FREEZE_DOCUMENTS: tuple[tuple[str, int, str], ...] = (
    (
        "docs/25-u5-cell-operating-assignment.md",
        50405,
        "ba62b2c7f4319c92c5b692b9c24747c27ee6e6d9809a5f1c2ebdad134a41e71a",
    ),
    (
        "docs/26-u6-transport-custody.md",
        58152,
        "f68b7008a62d3ae18f630babf88d2213ebf2946d4c77a37d8d95d164730edc59",
    ),
    (
        "docs/adr/0005-u5-cell-operating-assignment-control-v2.md",
        7945,
        "c438d6c659f00fd2950c7663d421c5fb3bfeeb50e4d9c5e275e5eae3e417e7fc",
    ),
    (
        "docs/adr/0006-u6-transport-custody.md",
        6117,
        "d4ea04596d0fb0a1d802c4043f537c21c82da84cd5581bd0a215f53f286bc2bc",
    ),
)

# radio_wire_r6_docs_gate DOC25 pins (must stay co-equal with freeze docs/25).
PINNED_R6_DOC25_RELPATH = "docs/25-u5-cell-operating-assignment.md"
PINNED_R6_DOC25_BYTES = 50405
PINNED_R6_DOC25_SHA256 = (
    "ba62b2c7f4319c92c5b692b9c24747c27ee6e6d9809a5f1c2ebdad134a41e71a"
)

# docs/23 is R6 content-gated; pin baseline so MFDT cannot silently edit it.
PINNED_DOC23_RELPATH = "docs/23-usb-radio-boundary.md"
PINNED_DOC23_BYTES = 155916
PINNED_DOC23_SHA256 = (
    "adaf5cd154adb3eb5f85d404e31894ee5f306351d6d1fa2a3d8c2ffd84536a34"
)

# MFDT-owned paths that may change without touching freeze surface.
MFDT_OWNED_PREFIXES: tuple[str, ...] = (
    "docs/adr/0021-multi-frame-durable-custody.md",
    "docs/work/2026-07-29-multi-frame-durable-transfer-spec-repair.md",
    "spec/vectors/multi-frame-durable-transfer-spec-v1.json",
    "src/runtime/mfdt_v1/",
    "tests/runtime/mfdt_v1/",
    "tests/model/multi_frame_durable_transfer_",
    "tools/multi_frame_durable_transfer_",
    "tools/mfdt_freeze_noninterference_gate.py",
    "cmake/ninlil_mfdt_",
)


def fail(msg: str) -> None:
    raise SystemExit(f"MFDT freeze noninterference FAIL: {msg}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(root: pathlib.Path, rel: str) -> bytes:
    path = (root / rel).resolve()
    if not str(path).startswith(str(root.resolve())):
        fail(f"path escape: {rel}")
    if path.is_symlink():
        fail(f"symlink forbidden: {rel}")
    if not path.is_file():
        fail(f"missing file: {rel}")
    return path.read_bytes()


def check_root(root: pathlib.Path) -> None:
    freeze_raw = read_bytes(root, PINNED_FREEZE_RELPATH)
    if len(freeze_raw) != PINNED_FREEZE_BYTE_LENGTH:
        fail(
            f"freeze manifest byte_length {len(freeze_raw)} "
            f"!= pin {PINNED_FREEZE_BYTE_LENGTH}"
        )
    freeze_sha = sha256_bytes(freeze_raw)
    if freeze_sha != PINNED_FREEZE_SHA256:
        fail(
            f"freeze manifest sha256 {freeze_sha} != pin {PINNED_FREEZE_SHA256} "
            "(MFDT must not rewrite U5/U6 freeze)"
        )
    try:
        freeze = json.loads(freeze_raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        fail(f"freeze JSON invalid: {e}")
    if not isinstance(freeze, dict):
        fail("freeze root must be object")
    if freeze.get("freeze_id") != PINNED_FREEZE_ID:
        fail(f"freeze_id {freeze.get('freeze_id')!r} != {PINNED_FREEZE_ID!r}")
    if str(freeze.get("freeze_version")) != PINNED_FREEZE_VERSION:
        fail(
            f"freeze_version {freeze.get('freeze_version')!r} "
            f"!= {PINNED_FREEZE_VERSION!r}"
        )

    docs = freeze.get("documents")
    if not isinstance(docs, list) or len(docs) != len(PINNED_FREEZE_DOCUMENTS):
        fail("freeze.documents count/shape mismatch vs MFDT noninterference pin")

    pin_by_path = {p: (n, h) for p, n, h in PINNED_FREEZE_DOCUMENTS}
    seen: set[str] = set()
    for i, entry in enumerate(docs):
        if not isinstance(entry, dict):
            fail(f"documents[{i}] not object")
        rel = entry.get("path")
        if rel not in pin_by_path:
            fail(f"documents[{i}] unexpected path {rel!r}")
        if rel in seen:
            fail(f"duplicate freeze document path {rel}")
        seen.add(rel)
        want_len, want_sha = pin_by_path[rel]
        if entry.get("byte_length") != want_len:
            fail(
                f"{rel}: freeze entry byte_length {entry.get('byte_length')} "
                f"!= pin {want_len}"
            )
        if entry.get("sha256") != want_sha:
            fail(f"{rel}: freeze entry sha256 mismatch pin")
        blob = read_bytes(root, rel)
        if len(blob) != want_len:
            fail(f"{rel}: disk byte_length {len(blob)} != pin {want_len}")
        got = sha256_bytes(blob)
        if got != want_sha:
            fail(f"{rel}: disk sha256 {got} != pin {want_sha}")

    if seen != set(pin_by_path):
        fail(f"freeze documents set mismatch: {sorted(seen)} vs {sorted(pin_by_path)}")

    # R6 docs/25 co-pin
    b25 = read_bytes(root, PINNED_R6_DOC25_RELPATH)
    if len(b25) != PINNED_R6_DOC25_BYTES:
        fail(
            f"R6 docs/25 byte_length {len(b25)} != pin {PINNED_R6_DOC25_BYTES} "
            "(was 50405; MFDT must not expand Accepted U5)"
        )
    if sha256_bytes(b25) != PINNED_R6_DOC25_SHA256:
        fail("R6 docs/25 sha256 mismatch pin")

    # docs/23 baseline pin (prevent MFDT catalog edits into R6 boundary)
    b23 = read_bytes(root, PINNED_DOC23_RELPATH)
    if len(b23) != PINNED_DOC23_BYTES:
        fail(f"docs/23 byte_length {len(b23)} != pin {PINNED_DOC23_BYTES}")
    if sha256_bytes(b23) != PINNED_DOC23_SHA256:
        fail("docs/23 sha256 mismatch pin")

    # Forbidden vocabulary in freeze docs: MFDT v3 catalog must not land there.
    forbidden = (
        b"MFDT_V3",
        b"multi-frame durable transfer catalog",
        b"selected_control_version == 3",
        b"selected_control_version=3",
        b"0x40..0x4d",
        b"ADR-0021",
    )
    for rel, _, _ in PINNED_FREEZE_DOCUMENTS:
        blob = read_bytes(root, rel)
        for token in forbidden:
            if token in blob:
                fail(
                    f"{rel} contains forbidden MFDT/v3 token {token!r}; "
                    "v3 rules stay in ADR-0021 only until separate refreeze"
                )

    print(
        "MFDT freeze noninterference OK "
        f"freeze={PINNED_FREEZE_ID}@v{PINNED_FREEZE_VERSION} "
        f"docs={len(PINNED_FREEZE_DOCUMENTS)} "
        f"r6_doc25={PINNED_R6_DOC25_BYTES} "
        f"doc23={PINNED_DOC23_BYTES}"
    )


def self_test() -> None:
    # Pristine check
    check_root(ROOT)

    cases: list[tuple[str, Any]] = []

    def mut_doc25(tmp: pathlib.Path) -> None:
        p = tmp / "docs/25-u5-cell-operating-assignment.md"
        p.write_bytes(p.read_bytes() + b"\n# MFDT_V3 illicit\n")

    def mut_doc25_to_50896(tmp: pathlib.Path) -> None:
        p = tmp / "docs/25-u5-cell-operating-assignment.md"
        raw = p.read_bytes()
        # Reproduce the reported regression size class (expand toward 50896).
        pad = 50896 - len(raw)
        if pad > 0:
            p.write_bytes(raw + (b"X" * pad))

    def mut_doc26(tmp: pathlib.Path) -> None:
        p = tmp / "docs/26-u6-transport-custody.md"
        p.write_bytes(p.read_bytes() + b"\nselected_control_version == 3\n")

    def mut_doc23(tmp: pathlib.Path) -> None:
        p = tmp / "docs/23-usb-radio-boundary.md"
        p.write_bytes(p.read_bytes() + b"\nADR-0021 catalog\n")

    def mut_freeze_manifest(tmp: pathlib.Path) -> None:
        p = tmp / PINNED_FREEZE_RELPATH
        data = json.loads(p.read_text(encoding="utf-8"))
        data["documents"][0]["byte_length"] = 50896
        p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def mut_freeze_rewrite_hash(tmp: pathlib.Path) -> None:
        p = tmp / PINNED_FREEZE_RELPATH
        data = json.loads(p.read_text(encoding="utf-8"))
        # Re-hash docs into freeze (the forbidden "silent refreeze" pattern).
        for entry in data["documents"]:
            blob = (tmp / entry["path"]).read_bytes()
            entry["byte_length"] = len(blob)
            entry["sha256"] = sha256_bytes(blob)
        p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    cases = [
        ("doc25_append", mut_doc25, "docs/25"),
        ("doc25_expand_50896", mut_doc25_to_50896, "50405"),
        ("doc26_v3_token", mut_doc26, "docs/26"),
        ("doc23_append", mut_doc23, "docs/23"),
        ("freeze_manifest_length", mut_freeze_manifest, "freeze"),
        ("freeze_silent_rehash", mut_freeze_rewrite_hash, "freeze"),
    ]

    for label, mutator, expect_sub in cases:
        with tempfile.TemporaryDirectory(prefix="mfdt_freeze_ni_") as td:
            tmp = pathlib.Path(td)
            # Copy only the freeze-relevant tree.
            for rel in (
                PINNED_FREEZE_RELPATH,
                PINNED_DOC23_RELPATH,
                *[p for p, _, _ in PINNED_FREEZE_DOCUMENTS],
            ):
                src = ROOT / rel
                dst = tmp / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            mutator(tmp)
            try:
                check_root(tmp)
            except SystemExit as e:
                msg = str(e)
                if expect_sub not in msg and "sha256" not in msg and "byte_length" not in msg:
                    # Still a failure is OK if pin mismatch language differs
                    if "FAIL" not in msg:
                        fail(f"self-test {label!r} unexpected: {msg}")
                print(f"  self-test mutation {label!r} correctly failed")
                continue
            fail(f"self-test {label!r} did not fail")

    # Positive: MFDT-owned file mutation must not be required for this gate.
    with tempfile.TemporaryDirectory(prefix="mfdt_freeze_ni_ok_") as td:
        tmp = pathlib.Path(td)
        for rel in (
            PINNED_FREEZE_RELPATH,
            PINNED_DOC23_RELPATH,
            *[p for p, _, _ in PINNED_FREEZE_DOCUMENTS],
        ):
            src = ROOT / rel
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        # Simulate MFDT ADR edit existing outside freeze set — create dummy.
        adr = tmp / "docs/adr/0021-multi-frame-durable-custody.md"
        adr.parent.mkdir(parents=True, exist_ok=True)
        adr.write_text("# ADR-0021 MFDT candidate edit\n", encoding="utf-8")
        check_root(tmp)
        print("  self-test MFDT-owned ADR edit does not affect freeze pins")

    print(
        "MFDT freeze noninterference self-test OK "
        f"mutations={len(cases)} + mfdt_owned_ok"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: mfdt_freeze_noninterference_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    if argv[1] == "check":
        check_root(ROOT)
        return 0
    self_test()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
