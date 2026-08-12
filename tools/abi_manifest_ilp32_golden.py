#!/usr/bin/env python3
"""Generate/check the ILP32 little-endian ABI manifest from a cross compiler."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile


REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCE = REPO / "tools/abi_manifest_ilp32_authority.c"
RECORD_BYTES = 136
VALUE_OFFSET = 128
REQUIRED_TARGET = {
    "format_version": 1,
    "abi_version": 1,
    "target.pointer_bits": 32,
    "target.long_bits": 32,
    "target.int_bits": 32,
    "target.size_t_bits": 32,
}


def compiler_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"tool not found: {name}")
    return path


def generate(cc_name: str, objcopy_name: str) -> str:
    cc = compiler_tool(cc_name)
    objcopy = compiler_tool(objcopy_name)
    with tempfile.TemporaryDirectory(prefix="ninlil-abi-ilp32-") as temp:
        root = pathlib.Path(temp)
        object_file = root / "authority.o"
        binary_file = root / "authority.bin"
        subprocess.run(
            [
                cc,
                "-std=c11",
                "-ffreestanding",
                f"-I{REPO / 'include'}",
                f"-I{REPO / 'tools'}",
                "-c",
                str(SOURCE),
                "-o",
                str(object_file),
            ],
            check=True,
        )
        subprocess.run(
            [objcopy, "-O", "binary", "-j", ".ninlil_abi_authority", str(object_file), str(binary_file)],
            check=True,
        )
        raw = binary_file.read_bytes()
    return render(raw)


def render(raw: bytes) -> str:
    if len(raw) < RECORD_BYTES or len(raw) % RECORD_BYTES:
        raise RuntimeError(f"invalid authority section size: {len(raw)}")
    target: dict[str, int] = {}
    constants: list[tuple[str, int]] = []
    structs: list[tuple[str, str, int]] = []
    saw_end = False
    for offset in range(0, len(raw), RECORD_BYTES):
        record = raw[offset : offset + RECORD_BYTES]
        kind = chr(record[0])
        name = record[1:VALUE_OFFSET].split(b"\0", 1)[0].decode("ascii")
        value = int.from_bytes(record[VALUE_OFFSET:RECORD_BYTES], "little")
        if kind == "Z":
            if name or value:
                raise RuntimeError("invalid authority terminator")
            saw_end = True
            if any(raw[offset + RECORD_BYTES :]):
                raise RuntimeError("authority data after terminator")
            break
        if saw_end or kind not in {"V", "C", "S", "A", "F"} or not name:
            raise RuntimeError("invalid authority record")
        if kind == "V":
            target[name] = value
        elif kind == "C":
            constants.append((name, value))
        else:
            structs.append((kind, name, value))
    if not saw_end or target != REQUIRED_TARGET:
        raise RuntimeError(f"unexpected target authority: {target}")
    lines = [
        "format_version=1",
        "abi_version=0x0001",
        "target.pointer_bits=32",
        "target.long_bits=32",
        "target.int_bits=32",
        "target.size_t_bits=32",
        "target.int_model=ILP32",
        "target.endian=little",
        "target.id=ILP32-le-32",
        "",
        "[constants]",
    ]
    lines.extend(f"constant {name} 0x{value:016x}" for name, value in constants)
    lines.extend(("", "[structs]"))
    counts = {"C": len(constants), "S": 0, "F": 0}
    for kind, name, value in structs:
        if kind == "S":
            lines.append(f"struct {name} size={value}")
            counts["S"] += 1
        elif kind == "A":
            lines.append(f"align {name} value={value}")
        else:
            lines.append(f"field {name} offset={value}")
            counts["F"] += 1
    lines.extend(
        (
            "",
            "[coverage]",
            f"coverage.constants={counts['C']}",
            f"coverage.structs={counts['S']}",
            f"coverage.fields={counts['F']}",
            "",
        )
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("golden", type=pathlib.Path)
    parser.add_argument("--cc", default="arm-none-eabi-gcc")
    parser.add_argument("--objcopy", default="arm-none-eabi-objcopy")
    args = parser.parse_args()
    try:
        actual = generate(args.cc, args.objcopy)
        if args.command == "generate":
            args.golden.write_text(actual, encoding="utf-8")
        elif args.golden.read_text(encoding="utf-8") != actual:
            print("abi_manifest_ilp32_golden FAIL: golden mismatch", file=sys.stderr)
            return 1
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"abi_manifest_ilp32_golden FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"abi_manifest_ilp32_golden {args.command} OK: {args.golden}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
