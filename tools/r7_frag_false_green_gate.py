#!/usr/bin/env python3
"""
Fail-closed test lint for r7_frag host tests.

Rejects always-true assertions and over-broad multi-status OR chains that
mask production path failures (false-green).

Forbidden:
  - expect_t("...", 1) / expect_t("...", 1u)  (constant true)
  - expect_t("...", true) with C true as literal 1 in second arg only
  - expect_t / expect_i conditions with 4+ status alternatives OR'd together
    when PROD_OK is one branch (masks R1/R2/N6 failures as green)

Exit 0 if clean; 1 if any finding.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_GLOBS = [
    "tests/radio/r7_frag/**/*.c",
]

# expect_t("label", 1) or expect_t("label", 1u)
ALWAYS_TRUE = re.compile(
    r"""expect_t\s*\(\s*"[^"]*"\s*,\s*1u?\s*\)""",
    re.MULTILINE,
)

# Broad OR of many PROD status codes (4+ alternatives) — false-green risk
BROAD_OR = re.compile(
    r"""expect_[ti]\s*\([^;]*?
        (?:NINLIL_R7_FRAG_PROD_OK|NINLIL_R7_FRAG_SESS_OK)
        (?:\s*\|\|\s*st\s*==\s*NINLIL_R7_FRAG_(?:PROD|SESS)_\w+){3,}
    """,
    re.MULTILINE | re.DOTALL | re.VERBOSE,
)

# Soft optional failure markers that always pass
OPTIONAL_FAIL = re.compile(
    r"""expect_t\s*\(\s*"(?:[^"]*optional[^"]*|[^"]*may exhaust[^"]*)"\s*,\s*1u?\s*\)""",
    re.IGNORECASE,
)


def iter_test_files() -> list[Path]:
    out: list[Path] = []
    for g in TEST_GLOBS:
        out.extend(ROOT.glob(g))
    return sorted(set(out))


def main() -> int:
    findings: list[str] = []
    for path in iter_test_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for m in ALWAYS_TRUE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            findings.append(f"{rel}:{line}: always-true expect_t(..., 1)")
        for m in OPTIONAL_FAIL.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            findings.append(f"{rel}:{line}: optional always-true assert")
        for m in BROAD_OR.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = re.sub(r"\s+", " ", m.group(0))[:120]
            findings.append(
                f"{rel}:{line}: over-broad multi-status OR (false-green): {snippet}"
            )

    if findings:
        print("r7_frag_false_green_gate: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("r7_frag_false_green_gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
