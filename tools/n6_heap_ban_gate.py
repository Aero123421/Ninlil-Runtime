#!/usr/bin/env python3
"""Reject malloc/calloc/realloc/free in N6 production sources and archives.

Source scan: exact three N6 production TUs (call-site regex, non-comment).
Archive scan: extract the exact three N6 members from the production archive,
run nm per object, reject defined or undefined malloc/calloc/realloc/free.

Non-N6 members of the same archive are ignored (no false positive).

self-test: synthetic otherwise-valid archive with one mutated N6 object must
fail with a specific heap error; unrelated non-N6 heap object alone must not
trip the N6 member check.

PASS ≠ product GO.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HEAP = ("malloc", "calloc", "realloc", "free")
N6_SRC = (
    "src/radio/n6_context_store.c",
    "src/radio/n6_record_codec.c",
    "src/radio/n6_crypto_host.c",
)
# Exact archive member basenames (production object names).
N6_AR_OBJECTS = (
    "n6_record_codec.c.o",
    "n6_crypto_host.c.o",
    "n6_context_store.c.o",
)

# nm symbol types: defined code/data/bss/common, or undefined.
_NM_DEF = frozenset("TtDdBbCcSsRrVvWwAa")
_NM_UNDEF = frozenset("U")


def check_sources(root: Path) -> list[str]:
    errs: list[str] = []
    call_re = re.compile(r"\b(malloc|calloc|realloc|free)\s*\(")
    # Boot scratch must be per-object; process-global mutable scratch is banned.
    static_scratch_re = re.compile(
        r"\bstatic\s+n6_boot_scratch_t\b|\bstatic\s+struct\s+n6_boot_scratch\b"
    )
    for rel in N6_SRC:
        p = root / rel
        if not p.is_file():
            errs.append(f"missing {rel}")
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("/*") or s.startswith("*") or s.startswith("//"):
                continue
            if call_re.search(line):
                errs.append(f"{rel}:{i}: heap API {line.strip()}")
            if rel.endswith("n6_context_store.c") and static_scratch_re.search(line):
                errs.append(
                    f"{rel}:{i}: process-global boot scratch banned "
                    f"(use per-object boot_scratch): {line.strip()}"
                )
    return errs


def _ar_list(archive: Path) -> list[str]:
    out = subprocess.check_output(["ar", "t", str(archive)], stderr=subprocess.STDOUT)
    return [
        ln.decode("utf-8", errors="replace").strip()
        for ln in out.splitlines()
        if ln.strip()
    ]


def _normalize_sym(name: str) -> str:
    n = name.strip()
    if n.startswith("_"):
        n = n[1:]
    # Some toolchains prefix with module$ etc.; take trailing identifier.
    if "." in n:
        n = n.rsplit(".", 1)[-1]
    return n


def _nm_heap_hits(obj: Path) -> list[str]:
    """Return human-readable heap symbol hits from nm -a on one object."""
    hits: list[str] = []
    try:
        out = subprocess.check_output(
            ["nm", "-a", str(obj)], stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        return [f"nm failed on {obj.name}: {e.output!r}"]
    except FileNotFoundError:
        return ["nm not found on PATH"]

    for raw in out.splitlines():
        line = raw.decode("utf-8", errors="replace").rstrip()
        if not line.strip():
            continue
        # Formats:
        #   "0000000000000000 T _malloc"
        #   "                 U _free"
        #   "n6_context_store.c.o: ..." (archive multi-header — ignore when single .o)
        parts = line.split()
        if len(parts) < 2:
            continue
        # Find type letter: either parts[0] is type (undefined) or parts[1]
        type_ch = ""
        sym = ""
        if len(parts) >= 3 and len(parts[1]) == 1:
            type_ch = parts[1]
            sym = parts[2]
        elif len(parts) >= 2 and len(parts[0]) == 1:
            type_ch = parts[0]
            sym = parts[1]
        else:
            continue
        if type_ch not in _NM_DEF and type_ch not in _NM_UNDEF:
            continue
        base = _normalize_sym(sym)
        if base in HEAP:
            kind = "undefined" if type_ch in _NM_UNDEF else "defined"
            hits.append(f"{kind} {base} ({line.strip()})")
    return hits


def check_archive(archive: Path) -> list[str]:
    """Extract exact three N6 members and nm each; non-N6 members ignored."""
    errs: list[str] = []
    if not archive.is_file():
        return [f"archive missing {archive}"]

    try:
        members = _ar_list(archive)
    except Exception as e:
        return [f"ar t failed: {e}"]

    # Require each N6 member exactly once (path suffix match for nested names).
    member_map: dict[str, list[str]] = {name: [] for name in N6_AR_OBJECTS}
    for m in members:
        base = Path(m).name
        if base in member_map:
            member_map[base].append(m)

    for name in N6_AR_OBJECTS:
        found = member_map[name]
        if len(found) == 0:
            errs.append(f"archive missing N6 member {name}")
        elif len(found) > 1:
            errs.append(f"archive duplicate N6 member {name}: {found}")

    if errs:
        return errs

    with tempfile.TemporaryDirectory(prefix="n6_heap_ban_") as td:
        tdir = Path(td)
        for name in N6_AR_OBJECTS:
            member = member_map[name][0]
            # Extract one member into temp dir.
            try:
                subprocess.check_call(
                    ["ar", "x", str(archive.resolve()), member],
                    cwd=str(tdir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as e:
                errs.append(f"ar x failed for {member}: {e}")
                continue
            # ar x may recreate nested path or basename
            candidates = [
                tdir / Path(member).name,
                tdir / member,
            ]
            # Also search
            obj = None
            for c in candidates:
                if c.is_file():
                    obj = c
                    break
            if obj is None:
                found_files = list(tdir.rglob(Path(member).name))
                if found_files:
                    obj = found_files[0]
            if obj is None or not obj.is_file():
                errs.append(f"extracted object missing for {name}")
                continue
            hits = _nm_heap_hits(obj)
            for h in hits:
                if h.startswith("nm failed") or h.startswith("nm not"):
                    errs.append(f"{name}: {h}")
                else:
                    errs.append(f"{name}: heap symbol {h}")
    return errs


def _compile_obj(src: str, out: Path) -> None:
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        raise RuntimeError("no C compiler (cc/clang) for self-test")
    r = subprocess.run(
        [cc, "-c", "-x", "c", "-o", str(out), "-"],
        input=src.encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"compile failed rc={r.returncode}: "
            f"{r.stderr.decode('utf-8', errors='replace')}"
        )


def _make_archive(path: Path, objects: list[Path]) -> None:
    if path.exists():
        path.unlink()
    cmd = ["ar", "rcs", str(path)] + [str(o) for o in objects]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def self_test(root: Path) -> int:
    fails = 0

    e = check_sources(root)
    if e:
        print("SELF-TEST FAIL: real tree has heap", e)
        fails += 1
    else:
        print("SELF-TEST OK: real tree no heap calls")

    try:
        with tempfile.TemporaryDirectory(prefix="n6_heap_self_") as td:
            tdir = Path(td)
            clean_codec = tdir / "n6_record_codec.c.o"
            clean_crypto = tdir / "n6_crypto_host.c.o"
            clean_store = tdir / "n6_context_store.c.o"
            dirty_store = tdir / "dirty_n6_context_store.c.o"
            other_heap = tdir / "unrelated_other.c.o"

            _compile_obj("int n6_codec_ok(void){return 0;}\n", clean_codec)
            _compile_obj("int n6_crypto_ok(void){return 1;}\n", clean_crypto)
            _compile_obj("int n6_store_ok(void){return 2;}\n", clean_store)
            _compile_obj(
                "#include <stdlib.h>\n"
                "void *n6_store_bad(void){return malloc(1);}\n",
                dirty_store,
            )
            _compile_obj(
                "#include <stdlib.h>\n"
                "void *unrelated_heap(void){return calloc(1,1);}\n",
                other_heap,
            )

            # (A) Valid N6 triplet only — must pass archive check
            good_ar = tdir / "libn6_good.a"
            _make_archive(good_ar, [clean_codec, clean_crypto, clean_store])
            ge = check_archive(good_ar)
            if ge:
                print("SELF-TEST FAIL: clean N6 archive should pass", ge)
                fails += 1
            else:
                print("SELF-TEST OK: clean N6 archive passes")

            # (B) Mutated N6 object (heap in context_store) — specific error
            bad_ar = tdir / "libn6_bad.a"
            # Rename dirty object to exact member name
            dirty_named = tdir / "n6_context_store.c.o"
            # keep clean_store path for good; use separate dirty with exact name
            if dirty_named.exists():
                dirty_named.unlink()
            shutil.copy2(dirty_store, dirty_named)
            _make_archive(bad_ar, [clean_codec, clean_crypto, dirty_named])
            be = check_archive(bad_ar)
            if not any(
                "n6_context_store.c.o" in x and "malloc" in x for x in be
            ):
                print(
                    "SELF-TEST FAIL: expected n6_context_store malloc error",
                    be,
                )
                fails += 1
            else:
                print("SELF-TEST OK: mutated N6 object yields specific heap error")

            # (C) Clean N6 + unrelated non-N6 heap object — must not false-positive
            mix_ar = tdir / "libn6_mix.a"
            # re-create clean store member
            clean_store2 = tdir / "n6_context_store_clean.c.o"
            _compile_obj("int n6_store_ok2(void){return 3;}\n", clean_store2)
            store_member = tdir / "member_store" / "n6_context_store.c.o"
            store_member.parent.mkdir(exist_ok=True)
            shutil.copy2(clean_store2, store_member)
            # ar with basenames in cwd
            mix_objs_dir = tdir / "mix"
            mix_objs_dir.mkdir()
            for src, name in (
                (clean_codec, "n6_record_codec.c.o"),
                (clean_crypto, "n6_crypto_host.c.o"),
                (clean_store2, "n6_context_store.c.o"),
                (other_heap, "unrelated_other.c.o"),
            ):
                dst = mix_objs_dir / name
                shutil.copy2(src, dst)
            mix_ar = mix_objs_dir / "libmix.a"
            _make_archive(
                mix_ar,
                [
                    mix_objs_dir / "n6_record_codec.c.o",
                    mix_objs_dir / "n6_crypto_host.c.o",
                    mix_objs_dir / "n6_context_store.c.o",
                    mix_objs_dir / "unrelated_other.c.o",
                ],
            )
            me = check_archive(mix_ar)
            if me:
                print(
                    "SELF-TEST FAIL: non-N6 heap must not false-positive",
                    me,
                )
                fails += 1
            else:
                print(
                    "SELF-TEST OK: unrelated non-N6 heap object ignored"
                )

            # (D) missing N6 member
            miss_ar = tdir / "libn6_miss.a"
            _make_archive(miss_ar, [clean_codec, clean_crypto])
            miss_e = check_archive(miss_ar)
            if not any("missing N6 member" in x for x in miss_e):
                print("SELF-TEST FAIL: expected missing member", miss_e)
                fails += 1
            else:
                print("SELF-TEST OK: missing N6 member fails")

    except Exception as ex:
        print(f"SELF-TEST FAIL: exception {ex}")
        fails += 1

    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", nargs="?", default="check")
    ap.add_argument("--src-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument(
        "--archive",
        default=None,
        help="Production private archive (ninlil_runtime_private); "
        "required for full check",
    )
    args = ap.parse_args()
    root = Path(args.src_root)

    if args.command == "self-test":
        rc = self_test(root)
        print("n6_heap_ban_gate self-test:", "OK" if rc == 0 else "FAIL")
        return rc

    errs = check_sources(root)
    if not args.archive:
        errs.append(
            "archive required for production check "
            "(pass --archive $<TARGET_FILE:ninlil_runtime_private>)"
        )
    else:
        errs.extend(check_archive(Path(args.archive)))

    if errs:
        print("n6_heap_ban_gate FAIL:")
        for e in errs:
            print(" ", e)
        return 1
    print("n6_heap_ban_gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
