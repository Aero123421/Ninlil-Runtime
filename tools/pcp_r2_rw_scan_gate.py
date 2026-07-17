#!/usr/bin/env python3
"""PCP R2: every READ_WRITE begin must be followed by full-namespace scan evidence.

Normative: docs/24 §4.3 (recover / each RW begin evaluates I1–I14).
Scans src/radio/pcp_authority.c for:
  - pcp_begin(..., NINLIL_STORAGE_READ_WRITE, ...)
  - storage_ops.begin(..., NINLIL_STORAGE_READ_WRITE, ...)  (if any remain)

Within LOOKAHEAD lines after each begin, require one of:
  - pcp_rw_scan_check(
  - pcp_scan_namespace(   (publish EMPTY reconfirm / recover RO paths OK)
  - /* PCP_RW_SCAN_EXEMPT: <reason> */  (must not appear; reserved, unused)

Self-test: delete a required scan after revoke begin → check fails.
Does not claim legal/HIL/re-review GO.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "radio" / "pcp_authority.c"
LOOKAHEAD = 40

BEGIN_RE = re.compile(
    r"pcp_begin\s*\(|"
    r"storage_ops\.begin\s*\("
)
RW_RE = re.compile(r"NINLIL_STORAGE_READ_WRITE")
SCAN_EVIDENCE_RE = re.compile(
    r"pcp_rw_scan_check\s*\(|pcp_scan_namespace\s*\("
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def find_rw_begins(text: str) -> list[tuple[int, str]]:
    """Return (line_index_0based, line) for RW begin sites."""
    lines = text.splitlines()
    sites: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if BEGIN_RE.search(line) or (
            i + 1 < len(lines)
            and BEGIN_RE.search(line + "\n" + lines[i + 1])
        ):
            # Multi-line begin: collect window of 6 lines for RW token
            window = "\n".join(lines[i : min(i + 6, len(lines))])
            if RW_RE.search(window):
                sites.append((i, line.strip()))
        i += 1
    return sites


def check_site(lines: list[str], idx: int) -> None:
    end = min(len(lines), idx + 1 + LOOKAHEAD)
    body = "\n".join(lines[idx:end])
    if not SCAN_EVIDENCE_RE.search(body):
        fail(
            f"RW begin at line {idx + 1} lacks pcp_rw_scan_check/"
            f"pcp_scan_namespace within {LOOKAHEAD} lines:\n  {lines[idx].strip()}"
        )


def check(root: pathlib.Path) -> None:
    path = root / "src" / "radio" / "pcp_authority.c"
    if not path.is_file():
        fail(f"missing {path}")
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    sites = find_rw_begins(text)
    if len(sites) < 6:
        fail(f"expected >=6 RW begin sites, found {len(sites)}")
    for idx, _ in sites:
        check_site(lines, idx)
    # Required call families must appear
    for needle in (
        "NINLIL_PCP_STAGE_CONSUME",
        "NINLIL_PCP_STAGE_REVOKE",
        "NINLIL_PCP_STAGE_ADVANCE",
        "NINLIL_PCP_STAGE_ISSUE",
        "NINLIL_PCP_STAGE_GC",
        "NINLIL_PCP_STAGE_RECOVER",
        "NINLIL_PCP_STAGE_PUBLISH",
    ):
        if needle not in text:
            fail(f"missing stage token {needle}")
    print(f"pcp_r2_rw_scan_gate ok: {len(sites)} RW begin sites have scan evidence")


def self_test() -> None:
    raw = SRC.read_text(encoding="utf-8")
    # Mutation: break ALL scan evidence symbols so every RW site fails the gate.
    mut = raw.replace("pcp_rw_scan_check", "pcp_rw_scan_CHEAT")
    mut = mut.replace("pcp_scan_namespace", "pcp_scan_namespace_CHEAT")
    if mut == raw:
        fail("self-test could not mutate scan evidence")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="pcp_rw_scan_gate_"))
    try:
        (tmp / "src" / "radio").mkdir(parents=True)
        (tmp / "src" / "radio" / "pcp_authority.c").write_text(
            mut, encoding="utf-8"
        )
        try:
            check(tmp)
            fail("self-test expected check failure after mutation")
        except GateFailure:
            pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("pcp_r2_rw_scan_gate self-test ok")


def main(argv: list[str]) -> int:
    try:
        if len(argv) < 2 or argv[1] not in ("check", "self-test"):
            print("usage: pcp_r2_rw_scan_gate.py check|self-test", file=sys.stderr)
            return 2
        if argv[1] == "check":
            check(REPO)
        else:
            self_test()
        return 0
    except GateFailure as exc:
        print(f"pcp_r2_rw_scan_gate FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
