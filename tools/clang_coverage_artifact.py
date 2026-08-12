#!/usr/bin/env python3
"""Emit non-gating llvm-cov LCOV and uncovered-line artifacts for one executable."""
import argparse
import pathlib
import shutil
import subprocess
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=pathlib.Path, required=True)
    ap.add_argument("--profraw-dir", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--llvm-profdata", default="llvm-profdata")
    ap.add_argument("--llvm-cov", default="llvm-cov")
    args = ap.parse_args()
    raw = sorted(args.profraw_dir.glob("*.profraw"))
    if not args.binary.is_file() or not raw:
        print("clang_coverage_artifact: missing executable or .profraw input", file=sys.stderr)
        return 1
    tools = [shutil.which(args.llvm_profdata), shutil.which(args.llvm_cov)]
    if not all(tools):
        print("clang_coverage_artifact: llvm-profdata/llvm-cov unavailable", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    profile = args.out / "coverage.profdata"
    subprocess.run([tools[0], "merge", "-sparse", *map(str, raw), "-o", str(profile)], check=True)
    with (args.out / "coverage.lcov").open("wb") as out:
        subprocess.run([tools[1], "export", str(args.binary), f"-instr-profile={profile}", "-format=lcov"], check=True, stdout=out)
    with (args.out / "uncovered.txt").open("wb") as out:
        subprocess.run([tools[1], "show", str(args.binary), f"-instr-profile={profile}", "-format=text", "-show-line-counts-or-regions"], check=True, stdout=out)
    print(f"clang coverage artifact ok: profraw={len(raw)} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
