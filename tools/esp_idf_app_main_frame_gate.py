#!/usr/bin/env python3
"""Official smoke app_main stack-frame regression gate (docs/22).

Compares CONFIG_ESP_MAIN_TASK_STACK_SIZE against the Xtensa ENTRY frame of
app_main in the linked ELF. Uses the official ESP-IDF toolchain objdump
explicitly — never false-greens when the tool is missing.

Baseline observed on v5.5.3 / esp32s3: app_main entry frame 496 B vs
CONFIG_ESP_MAIN_TASK_STACK_SIZE 3584 B.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Safety: require free margin so stack locals cannot silently re-approach
# CONFIG. Baseline 496/3584 leaves ~3 KiB; margin is absolute, not a ratio
# that green-washes growth up to the ceiling.
SAFE_MARGIN_BYTES = 1024
# Documented pin default; fail if sdkconfig drifts below this without review.
MIN_MAIN_STACK_BYTES = 3584

# Official xtensa-esp32s3-elf-objdump may emit either:
#   42007dc4:	36e103        	entry	a1, 496
#   42007dc4:03e136        entrya1, 0x1f0
# Frame size is decimal or 0x-hex (bytes, multiple of 8).
ENTRY_RE = re.compile(
    r"entry\s*a1\s*,\s*(0x[0-9a-f]+|\d+)\b",
    re.IGNORECASE,
)
SYM_RE = re.compile(r"^[0-9a-f]+\s+<app_main>:\s*$", re.IGNORECASE)
NEXT_SYM_RE = re.compile(r"^[0-9a-f]+\s+<\S+>:\s*$")
STACK_CFG_RE = re.compile(
    r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)\s*$", re.MULTILINE
)


def fail(msg: str) -> None:
    print(f"esp_idf_app_main_frame_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_main_stack(sdkconfig: pathlib.Path) -> int:
    if not sdkconfig.is_file():
        fail(f"missing sdkconfig: {sdkconfig}")
    text = sdkconfig.read_text(encoding="utf-8", errors="replace")
    m = STACK_CFG_RE.search(text)
    if not m:
        fail(f"CONFIG_ESP_MAIN_TASK_STACK_SIZE not found in {sdkconfig}")
    return int(m.group(1))


def resolve_objdump(explicit: str | None) -> str:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend(
        [
            "xtensa-esp32s3-elf-objdump",
            "xtensa-esp-elf-objdump",
        ]
    )
    for name in candidates:
        path = shutil.which(name) if "/" not in name and "\\" not in name else name
        if path and pathlib.Path(path).exists() or shutil.which(name):
            found = shutil.which(name) if not pathlib.Path(name).exists() else name
            if found:
                return found
    fail(
        "xtensa objdump not found (need xtensa-esp32s3-elf-objdump from "
        "official ESP-IDF toolchain; refusing false-green)"
    )
    raise AssertionError("unreachable")


def parse_app_main_frame(objdump: str, elf: pathlib.Path) -> int:
    if not elf.is_file():
        fail(f"missing ELF: {elf}")
    try:
        proc = subprocess.run(
            [objdump, "-d", str(elf)],
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        fail(f"objdump failed ({exc.returncode}): {exc.stderr[:500]}")
    except FileNotFoundError:
        fail(f"objdump executable missing: {objdump}")

    lines = proc.stdout.splitlines()
    in_app = False
    for line in lines:
        stripped = line.strip()
        if SYM_RE.match(stripped) or stripped.endswith("<app_main>:"):
            in_app = True
            continue
        if in_app:
            if NEXT_SYM_RE.match(stripped) and "app_main" not in stripped:
                break
            m = ENTRY_RE.search(line)
            if m:
                frame = int(m.group(1), 0)
                if frame <= 0:
                    fail(f"parsed non-positive app_main frame from: {line!r}")
                if frame % 8 != 0:
                    fail(f"app_main frame {frame} is not 8-byte aligned: {line!r}")
                return frame
    fail("could not parse app_main ENTRY a1, <frame> from objdump -d")
    raise AssertionError("unreachable")


def check(elf: pathlib.Path, sdkconfig: pathlib.Path, objdump: str | None) -> None:
    stack = read_main_stack(sdkconfig)
    if stack < MIN_MAIN_STACK_BYTES:
        fail(
            f"CONFIG_ESP_MAIN_TASK_STACK_SIZE={stack} < documented minimum "
            f"{MIN_MAIN_STACK_BYTES}"
        )
    od = resolve_objdump(objdump)
    frame = parse_app_main_frame(od, elf)
    if frame <= 0:
        fail(f"non-positive app_main frame {frame}")
    if frame + SAFE_MARGIN_BYTES > stack:
        fail(
            f"app_main frame {frame} B + margin {SAFE_MARGIN_BYTES} B "
            f"exceeds main stack {stack} B"
        )
    free = stack - frame
    print(
        "esp_idf_app_main_frame_gate OK: "
        f"frame={frame} stack={stack} free={free} margin>={SAFE_MARGIN_BYTES} "
        f"objdump={od}"
    )


def self_test() -> None:
    samples = (
        ("  42007dc4:\t36e103        \tentry\ta1, 496\n", 496),
        ("42007dc4:03e136        entrya1, 0x1f0\n", 0x1F0),
        ("42007dc4:03e136        entry a1, 0x1f0\n", 496),
    )
    for sample, expect in samples:
        m = ENTRY_RE.search(sample)
        if not m or int(m.group(1), 0) != expect:
            fail(f"self-test ENTRY parse failed for {sample!r}")
    if not STACK_CFG_RE.search("CONFIG_ESP_MAIN_TASK_STACK_SIZE=3584\n"):
        fail("self-test sdkconfig parse")
    print("esp_idf_app_main_frame_gate self-test OK")


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
    parser.add_argument(
        "--sdkconfig",
        type=pathlib.Path,
        default=REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "sdkconfig",
    )
    parser.add_argument(
        "--objdump",
        default=None,
        help="path or name of xtensa-esp32s3-elf-objdump",
    )
    args = parser.parse_args(argv[1:])
    if args.command == "self-test":
        self_test()
        return 0
    check(args.elf, args.sdkconfig, args.objdump)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
