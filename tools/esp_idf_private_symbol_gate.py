#!/usr/bin/env python3
"""Official ELF private-symbol visibility gate (docs/22).

Requires readelf (or xtensa-*-readelf) and refuses false-green when the
tool is missing. Private helpers must not appear as GLOBAL DEFAULT.
cell_config_stage_nested_owner must be absent (static inline).
Public installed headers must not declare these private symbols.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Must not be GLOBAL DEFAULT in the linked smoke ELF.
PRIVATE_FUNCS = (
    "ninlil_esp_idf_owner_config_stage",
)

# Must be completely absent (static inline / no external symbol).
ABSENT_FUNCS = (
    "ninlil_esp_idf_cell_config_stage_nested_owner",
)

PUBLIC_HEADERS = (
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "owner_task.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "cell_agent.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "owner_task_storage.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "cell_agent_storage.h",
    REPO_ROOT / "include" / "ninlil" / "platform.h",
    REPO_ROOT / "include" / "ninlil" / "runtime.h",
    REPO_ROOT / "include" / "ninlil" / "service.h",
    REPO_ROOT / "include" / "ninlil" / "transaction.h",
    REPO_ROOT / "include" / "ninlil" / "version.h",
)

# readelf -Ws line sample (GNU):
#   123: 4200a3fc   64 FUNC    GLOBAL DEFAULT   12 ninlil_esp_idf_owner_config_stage
SYM_LINE_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\w+\s+(\w+)\s+(\w+)\s+\S+\s+(\S+)\s*$"
)


def fail(msg: str) -> None:
    print(f"esp_idf_private_symbol_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def resolve_readelf(explicit: str | None) -> str:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend(
        [
            "xtensa-esp32s3-elf-readelf",
            "xtensa-esp-elf-readelf",
            "readelf",
            "llvm-readelf",
        ]
    )
    for name in candidates:
        if pathlib.Path(name).exists():
            return name
        found = shutil.which(name)
        if found:
            return found
    fail(
        "readelf not found (need xtensa-esp32s3-elf-readelf or readelf; "
        "refusing false-green)"
    )
    raise AssertionError("unreachable")


def parse_symbols(readelf: str, elf: pathlib.Path) -> list[tuple[str, str, str]]:
    if not elf.is_file():
        fail(f"missing ELF: {elf}")
    try:
        proc = subprocess.run(
            [readelf, "-Ws", str(elf)],
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        fail(f"readelf failed ({exc.returncode}): {exc.stderr[:500]}")
    except FileNotFoundError:
        fail(f"readelf executable missing: {readelf}")

    out: list[tuple[str, str, str]] = []
    for line in proc.stdout.splitlines():
        m = SYM_LINE_RE.match(line)
        if not m:
            # llvm-readelf / alternate columns: fall back to token search
            if "ninlil_esp_idf_" not in line:
                continue
            tokens = line.split()
            if len(tokens) < 8:
                continue
            # try last token as name, bind/vis near end
            name = tokens[-1]
            bind = vis = None
            for t in tokens:
                if t in ("GLOBAL", "LOCAL", "WEAK"):
                    bind = t
                if t in ("DEFAULT", "HIDDEN", "INTERNAL", "PROTECTED"):
                    vis = t
            if bind and vis and name:
                out.append((name, bind, vis))
            continue
        bind, vis, name = m.group(1), m.group(2), m.group(3)
        out.append((name, bind, vis))
    return out


def check_public_headers() -> None:
    needles = list(PRIVATE_FUNCS) + list(ABSENT_FUNCS)
    for hdr in PUBLIC_HEADERS:
        if not hdr.is_file():
            fail(f"missing public header: {hdr}")
        text = hdr.read_text(encoding="utf-8", errors="replace")
        for n in needles:
            if n in text:
                fail(f"public header {hdr.relative_to(REPO_ROOT)} declares {n}")


def check(elf: pathlib.Path, readelf: str | None) -> None:
    check_public_headers()
    re_bin = resolve_readelf(readelf)
    syms = parse_symbols(re_bin, elf)
    by_name: dict[str, list[tuple[str, str]]] = {}
    for name, bind, vis in syms:
        by_name.setdefault(name, []).append((bind, vis))

    for name in ABSENT_FUNCS:
        if name in by_name:
            fail(f"{name} must be absent (static inline), found {by_name[name]}")

    for name in PRIVATE_FUNCS:
        entries = by_name.get(name)
        if not entries:
            # Hidden symbols may still appear; if fully stripped from dynsym
            # but present in symtab readelf -Ws should still show them.
            # Absence after full link would mean the helper was inlined away
            # or LTO'd — still OK for non-export, but owner_config_stage is
            # a .c TU and should remain as a symbol. Fail closed so we notice
            # accidental removal from the image.
            fail(f"{name} missing from ELF symtab (expected HIDDEN or LOCAL)")
        for bind, vis in entries:
            if bind == "GLOBAL" and vis == "DEFAULT":
                fail(f"{name} is GLOBAL DEFAULT (must be HIDDEN or LOCAL)")
            if bind not in ("GLOBAL", "LOCAL", "WEAK"):
                fail(f"{name} unexpected bind {bind}")
            if bind == "GLOBAL" and vis not in ("HIDDEN", "INTERNAL", "PROTECTED"):
                fail(f"{name} GLOBAL with non-private visibility {vis}")

    print(
        "esp_idf_private_symbol_gate OK: "
        f"private={list(PRIVATE_FUNCS)} absent={list(ABSENT_FUNCS)} "
        f"readelf={re_bin}"
    )


def self_test() -> None:
    sample = (
        "   123: 4200a3fc    64 FUNC    GLOBAL HIDDEN    12 "
        "ninlil_esp_idf_owner_config_stage\n"
    )
    m = SYM_LINE_RE.match(sample.strip())
    if not m or m.group(1) != "GLOBAL" or m.group(2) != "HIDDEN":
        fail("self-test readelf line parse")
    print("esp_idf_private_symbol_gate self-test OK")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument(
        "--elf",
        type=pathlib.Path,
        default=REPO_ROOT
        / "ports"
        / "esp-idf"
        / "smoke_app"
        / "build"
        / "ninlil_m3_basic_smoke.elf",
    )
    parser.add_argument("--readelf", default=None)
    args = parser.parse_args(argv[1:])
    if args.command == "self-test":
        self_test()
        return 0
    check(args.elf, args.readelf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
