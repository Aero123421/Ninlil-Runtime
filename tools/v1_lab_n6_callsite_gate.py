#!/usr/bin/env python3
"""Keep V1 accepted N6 entries behind one production-private owner."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


N6_SOURCE = "src/radio/n6_context_store.c"
OWNER_SOURCE = "src/transport/fabric_v1/v1_lab_n6_owner.c"
SYMBOLS = (
    "ninlil_n6_bind_local_identity_accepted",
    "ninlil_n6_bind_authority_stamp_accepted",
    "ninlil_n6_install_hop_accepted",
    "ninlil_n6_install_e2e_accepted",
)


def occurrences(files: dict[str, str]) -> dict[str, list[str]]:
    found = {symbol: [] for symbol in SYMBOLS}
    for path, source in files.items():
        for symbol in SYMBOLS:
            count = len(re.findall(rf"\b{re.escape(symbol)}\s*\(", source))
            found[symbol].extend([path] * count)
    return found


def validate(files: dict[str, str]) -> list[str]:
    errors: list[str] = []
    found = occurrences(files)
    for symbol, paths in found.items():
        unexpected = sorted(
            path for path in paths if path not in (N6_SOURCE, OWNER_SOURCE)
        )
        if unexpected:
            errors.append(f"{symbol}: unexpected production callsite(s): {unexpected}")
        if paths.count(N6_SOURCE) != 1:
            errors.append(
                f"{symbol}: expected one N6 definition, got {paths.count(N6_SOURCE)}"
            )
        if paths.count(OWNER_SOURCE) != 1:
            errors.append(
                f"{symbol}: expected one V1 owner call, got {paths.count(OWNER_SOURCE)}"
            )
    return errors


def load_sources(root: pathlib.Path) -> dict[str, str]:
    src = root / "src"
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(src.rglob("*.c"))
    }


def check(root: pathlib.Path) -> int:
    errors = validate(load_sources(root))
    if errors:
        print("v1_lab_n6_callsite_gate FAIL:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("v1_lab_n6_callsite_gate: OK (4 accepted entries, sole V1 owner)")
    return 0


def self_test() -> int:
    n6 = "\n".join(f"int {symbol}(void) {{ return 0; }}" for symbol in SYMBOLS)
    owner = "\n".join(f"void f_{i}(void) {{ {symbol}(); }}"
                      for i, symbol in enumerate(SYMBOLS))
    good = {N6_SOURCE: n6, OWNER_SOURCE: owner}
    if validate(good):
        print("v1_lab_n6_callsite_gate self-test FAIL: valid corpus rejected")
        return 1
    rogue = dict(good)
    rogue["src/radio/rogue.c"] = f"void x(void) {{ {SYMBOLS[0]}(); }}"
    if not validate(rogue):
        print("v1_lab_n6_callsite_gate self-test FAIL: rogue call accepted")
        return 1
    missing = dict(good)
    missing[OWNER_SOURCE] = owner.replace(f"{SYMBOLS[1]}();", "")
    if not validate(missing):
        print("v1_lab_n6_callsite_gate self-test FAIL: missing owner call accepted")
        return 1
    print("v1_lab_n6_callsite_gate self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "self-test"))
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    args = parser.parse_args()
    if args.mode == "self-test":
        return self_test()
    return check(args.root.resolve())


if __name__ == "__main__":
    sys.exit(main())
