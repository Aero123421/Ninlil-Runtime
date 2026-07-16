#!/usr/bin/env python3
"""Parse real -fstack-usage (.su) artifacts for the ESP storage port.

Fails if any recorded frame exceeds NINLIL_PORT_ESP_STORAGE_MAX_STACK_FRAME_BYTES
(default 2048). Does not accept regex-only claims without .su files when
--require-su is set (host CI after -fstack-usage build).

.su line format (GCC/Clang):
  path:line:col:function\\tframe_size\\tstatic/dynamic
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
HEADER = REPO / "ports/esp-idf/storage/include/ninlil_port/esp_storage.h"
DEFAULT_MAX = 2048

SU_LINE_RE = re.compile(
    r"^(?P<path>[^:]+):(?P<line>\d+):(?:\d+:)?(?P<func>[^\t]+)\t"
    r"(?P<size>\d+)\t(?P<qual>.*)$"
)


def fail(msg: str) -> None:
    print(f"esp_storage_stack_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def header_max_stack() -> int:
    text = HEADER.read_text(encoding="utf-8")
    m = re.search(
        r"#define\s+NINLIL_PORT_ESP_STORAGE_MAX_STACK_FRAME_BYTES\s+"
        r"\(\(size_t\)(\d+)u\)",
        text,
    )
    if not m:
        return DEFAULT_MAX
    return int(m.group(1))


def collect_su(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for p in paths:
        if p.is_file() and p.suffix == ".su":
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(p.rglob("*.su")))
    return files


def parse_su(path: pathlib.Path) -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = SU_LINE_RE.match(line)
        if not m:
            # Some toolchains emit slightly different spacing.
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].isdigit():
                func = parts[0].rsplit(":", 1)[-1]
                rows.append((str(path), func, int(parts[1])))
            continue
        rows.append((m.group("path"), m.group("func").strip(), int(m.group("size"))))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "roots",
        nargs="*",
        type=pathlib.Path,
        help=".su files or directories to scan",
    )
    ap.add_argument("--max", type=int, default=0, help="override max frame bytes")
    ap.add_argument(
        "--require-su",
        action="store_true",
        help="fail if no .su files found (host CI after -fstack-usage)",
    )
    ap.add_argument(
        "--require-model",
        action="store_true",
        help="require at least one .su covering esp_storage_model.c",
    )
    ap.add_argument(
        "--compiler-skip",
        default="",
        help="record an unsupported host compiler; ESP-IDF GCC remains authoritative",
    )
    args = ap.parse_args()
    if args.compiler_skip:
        print(
            "esp_storage_stack_gate SKIP: compiler="
            f"{args.compiler_skip}; production ESP-IDF GCC gate is required"
        )
        return
    max_bytes = args.max if args.max > 0 else header_max_stack()
    roots = args.roots or []
    su_files = collect_su(roots)

    if not su_files:
        if args.require_su:
            fail(
                "no .su artifacts found; build with -fstack-usage and pass "
                "the build directory"
            )
        print(
            "esp_storage_stack_gate OK: no .su inputs "
            f"(max={max_bytes}; pass build dir with --require-su for enforce)"
        )
        return

    worst: list[tuple[int, str, str]] = []
    parsed_rows = 0
    model_rows = 0
    for su in su_files:
        rows = parse_su(su)
        parsed_rows += len(rows)
        for path, func, size in rows:
            if "esp_storage_model" in path or "esp_storage_model" in str(su):
                model_rows += 1
            worst.append((size, func, f"{su}:{path}"))
            if size > max_bytes:
                fail(
                    f"stack frame {size}B > {max_bytes}B in {func} "
                    f"({su.name})"
                )

    if args.require_su and parsed_rows == 0:
        fail(".su files exist but contain no parseable frame rows")
    if args.require_model and model_rows == 0:
        fail("no parsed .su frame coverage for esp_storage_model.c")

    worst.sort(reverse=True)
    top = ", ".join(f"{fn}={sz}B" for sz, fn, _ in worst[:5])
    print(
        f"esp_storage_stack_gate OK: files={len(su_files)} "
        f"max_allowed={max_bytes} top=[{top}]"
    )


if __name__ == "__main__":
    main()
