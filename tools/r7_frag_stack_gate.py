#!/usr/bin/env python3
"""R7 private FRAG bounded-frame gate (ESP 4096-byte maximum exact).

Authority: cmake/ninlil_r7_frag_sources.cmake production relative sources.
Rules:
  - every production FRAG .c has exactly one .su under --su-dir
  - every parsed .su row is static or compiler-proven dynamic,bounded
  - unbounded dynamic rows are rejected outside sanitizer-only presence mode
  - every function frame <= 4096 (never raise ceiling)
  - recover_cu and restart_encode must appear and be under ceiling
  - structural: ESP component enables -Wframe-larger-than=4096 for FRAG

PASS ≠ RF/HIL/legal/software gap=0 alone.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile
from typing import Iterable

REPO = pathlib.Path(__file__).resolve().parents[1]
AUTHORITY = REPO / "cmake" / "ninlil_r7_frag_sources.cmake"
COMPONENT = REPO / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
CEILING = 4096
SOURCE_LINE_RE = re.compile(r"^\s*(src/radio/r7_frag/[A-Za-z0-9_.-]+\.c)\s*$")
# Production path frames (ESP PRODUCTION sources may omit lab session/durable).
REQUIRED_FUNCS_PRODUCTION = frozenset(
    {
        "ninlil_r7_frag_prod_rx_outer",
        "ninlil_r7_frag_prod_tx_frag_begin",
    }
)
# Lab path frames when durable/session .su present.
REQUIRED_FUNCS_LAB = frozenset(
    {
        "ninlil_r7_frag_dur_recover_cu",
        "ninlil_r7_frag_sess_restart_encode",
    }
)
REQUIRED_FUNCS = REQUIRED_FUNCS_PRODUCTION | REQUIRED_FUNCS_LAB
DYNAMIC_FRAME_KINDS = frozenset({"dynamic", "dynamic,bounded"})


def fail(msg: str) -> None:
    print(f"r7_frag_stack_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _parse_list_basenames(text: str, list_name: str) -> list[str]:
    if list_name not in text:
        return []
    block = text.split(list_name, 1)[1]
    block = block.split(")", 1)[0]
    names: list[str] = []
    for line in block.splitlines():
        m = SOURCE_LINE_RE.match(line)
        if m:
            names.append(pathlib.Path(m.group(1)).name)
    return names


def authority_basenames() -> list[str]:
    text = AUTHORITY.read_text(encoding="utf-8")
    names: list[str] = []
    for line in text.splitlines():
        m = SOURCE_LINE_RE.match(line)
        if m:
            names.append(pathlib.Path(m.group(1)).name)
    # Deduplicate while preserving order (PORTABLE expands prod+lab).
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    if len(out) < 6:
        fail(f"authority basenames too few: {out}")
    return out


def production_basenames() -> list[str]:
    text = AUTHORITY.read_text(encoding="utf-8")
    names = _parse_list_basenames(text, "NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES")
    if len(names) < 5:
        # Fallback: whole authority if PRODUCTION list absent (legacy).
        return authority_basenames()
    return names


def find_su_artifact(su_dir: pathlib.Path, basename_c: str) -> list[pathlib.Path]:
    """Match both basename.c.su and nested path …/basename.c.su."""
    expected = f"{basename_c}.su"
    if not su_dir.is_dir():
        return []
    return sorted(p for p in su_dir.rglob("*.su") if p.name == expected)


def parse_su_lines(
    lines: Iterable[str],
    *,
    allow_dynamic: bool = False,
) -> tuple[list[str], dict[str, tuple[int, str]]]:
    """Parse .su records.

    Production/ESP authoritative paths accept exact static frames and GCC's
    dynamic,bounded form, whose reported byte count is an upper bound.
    Sanitizer host builds rewrite frames to a compiler-specific dynamic form
    and inflate sizes.  When allow_dynamic=True, accept GCC/Clang dynamic
    kinds and skip the 4096 ceiling (presence + required-symbol registration
    still enforced).
    """
    errors: list[str] = []
    records: dict[str, tuple[int, str]] = {}
    for line_number, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line:
            continue
        columns = line.split("\t")
        if len(columns) != 3:
            errors.append(f"line {line_number}: expected 3 tab-separated columns")
            continue
        location, byte_text, kind = columns
        function = location.rsplit(":", 1)[-1]
        if not function or not byte_text.isdigit():
            errors.append(f"line {line_number}: invalid function/frame record")
            continue
        if kind != "static" and kind not in DYNAMIC_FRAME_KINDS:
            errors.append(
                f"{function}: frame kind must be static or a known dynamic kind, got {kind}"
            )
            continue
        if kind == "dynamic" and not allow_dynamic:
            errors.append(f"{function}: unbounded dynamic frame is forbidden")
            continue
        frame = int(byte_text)
        if not allow_dynamic and frame > CEILING:
            errors.append(f"{function}: frame {frame} exceeds {CEILING}")
        # static inlines may appear once per TU; keep the max frame.
        if function in records:
            if frame > records[function][0]:
                records[function] = (frame, kind)
        else:
            records[function] = (frame, kind)
    return errors, records


def structural_check() -> list[str]:
    errors: list[str] = []
    text = COMPONENT.read_text(encoding="utf-8")
    if "CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE" not in text:
        errors.append("component missing FRAG Kconfig gate")
    if f"-Wframe-larger-than={CEILING}" not in text:
        errors.append(
            f"component FRAG sources must set -Wframe-larger-than={CEILING}"
        )
    if "-fstack-usage" not in text:
        errors.append("component FRAG sources must set -fstack-usage")
    if "ninlil_r7_frag_sources.cmake" not in text:
        errors.append("component must include single FRAG source authority")
    return errors


def check_su_dir(
    su_dir: pathlib.Path,
    *,
    allow_dynamic: bool = False,
) -> list[str]:
    errors: list[str] = []
    # Prefer PRODUCTION set so ESP claim builds (no lab TUs) still gate.
    prod = production_basenames()
    all_names = authority_basenames()
    present_lab = any(
        find_su_artifact(su_dir, n)
        for n in ("r7_frag_session.c", "r7_frag_durable.c")
    )
    basenames = all_names if present_lab else prod
    files: list[pathlib.Path] = []
    for name in basenames:
        matches = find_su_artifact(su_dir, name)
        if len(matches) != 1:
            errors.append(
                f"{name}.su: expected exactly one artifact, got {len(matches)}"
            )
        else:
            files.append(matches[0])
    if errors:
        return errors
    lines: list[str] = []
    for path in files:
        try:
            lines.extend(path.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot read {path}: {exc}")
    parse_errs, records = parse_su_lines(lines, allow_dynamic=allow_dynamic)
    errors.extend(parse_errs)
    required = set(REQUIRED_FUNCS_PRODUCTION)
    if present_lab:
        required |= REQUIRED_FUNCS_LAB
    missing = sorted(required - records.keys())
    if missing:
        errors.append(f"required FRAG frames missing: {', '.join(missing)}")
    if not allow_dynamic:
        for fn, (frame, _kind) in records.items():
            if frame > CEILING:
                errors.append(f"{fn}: frame {frame} exceeds {CEILING}")
    return errors


def check(
    su_dir: pathlib.Path | None,
    *,
    allow_dynamic: bool = False,
) -> None:
    errors = structural_check()
    if su_dir is not None:
        errors.extend(check_su_dir(su_dir, allow_dynamic=allow_dynamic))
    if errors:
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        fail(f"{len(errors)} error(s)")
    mode = "structural-only"
    if su_dir is not None:
        mode = "sanitizer-dynamic" if allow_dynamic else "bounded-checked"
    print(
        f"r7_frag_stack_gate OK: ceiling={CEILING} "
        f"sources={len(authority_basenames())} "
        f"su={mode}"
    )


def self_test() -> None:
    check(None)
    bounded_lines = ["fixture.c:1:bounded_fn\t128\tdynamic,bounded"]
    bounded_errors, bounded_records = parse_su_lines(
        bounded_lines, allow_dynamic=False
    )
    if bounded_errors or "bounded_fn" not in bounded_records:
        fail("self-test rejected compiler-bounded dynamic frame")
    unbounded_errors, _ = parse_su_lines(
        ["fixture.c:1:unbounded_fn\t128\tdynamic"], allow_dynamic=False
    )
    if not any("unbounded dynamic" in error for error in unbounded_errors):
        fail("self-test accepted unbounded dynamic frame on authoritative path")
    over_errors, _ = parse_su_lines(
        ["fixture.c:1:bounded_over\t5000\tdynamic,bounded"],
        allow_dynamic=False,
    )
    if not any("exceeds" in error for error in over_errors):
        fail("self-test accepted over-ceiling compiler-bounded frame")
    # Synthetic .su under ceiling for required funcs + one source identity.
    basenames = authority_basenames()
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for idx, name in enumerate(basenames):
            path = root / f"{name}.su"
            lines = [
                f"{name}:1:fn_{idx}\t128\tstatic\n",
            ]
            if name == "r7_frag_prod_orch.c":
                lines.append(
                    "r7_frag_prod_orch.c:585:ninlil_r7_frag_prod_rx_outer\t960\tstatic\n"
                )
                lines.append(
                    "r7_frag_prod_orch.c:891:ninlil_r7_frag_prod_tx_frag_begin\t400\tstatic\n"
                )
            if name == "r7_frag_durable.c":
                lines.append(
                    "r7_frag_durable.c:216:ninlil_r7_frag_dur_recover_cu\t256\tstatic\n"
                )
            if name == "r7_frag_session.c":
                lines.append(
                    "r7_frag_session.c:1326:ninlil_r7_frag_sess_restart_encode\t192\tstatic\n"
                )
            path.write_text("".join(lines), encoding="utf-8")
        check(root)
        # Over-ceiling must fail.
        bad = root / "r7_frag_durable.c.su"
        bad.write_text(
            "r7_frag_durable.c:216:ninlil_r7_frag_dur_recover_cu\t5000\tstatic\n",
            encoding="utf-8",
        )
        try:
            check(root)
            fail("self-test accepted over-ceiling recover_cu")
        except SystemExit:
            pass
    check(None)
    print("r7_frag_stack_gate self-test OK")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "mode",
        choices=("check", "self-test", "list-production"),
    )
    ap.add_argument(
        "--su-dir",
        type=pathlib.Path,
        default=None,
        help="Directory containing production FRAG .su artifacts",
    )
    ap.add_argument(
        "--allow-dynamic",
        action="store_true",
        help=(
            "Accept sanitizer-inflated dynamic .su rows and skip 4096 ceiling. "
            "Authoritative normal builds must omit this flag (static only)."
        ),
    )
    args = ap.parse_args(argv[1:])
    if args.mode == "list-production":
        for basename in production_basenames():
            print(basename)
        return 0
    if args.mode == "self-test":
        self_test()
        return 0
    check(args.su_dir, allow_dynamic=bool(args.allow_dynamic))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
