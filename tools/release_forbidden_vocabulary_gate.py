#!/usr/bin/env python3
"""Release forbidden-vocabulary gate (repo-wide tracked tree).

Asserts zero hits of product-specific forbidden tokens across **all
git-tracked** release source / docs / archive content (not README-only).

Banned family (case-insensitive): the letter k, optional whitespace, optional
single hyphen/underscore/space, then the word guard; plus a known transposition
typo of that family. Patterns are assembled from fragments below so this file
never embeds a contiguous forbidden token. Alnum boundaries avoid ordinary
English such as "clock"+" "+"guard", "Block"+" "+"guard", or identifiers like
"ok_"+"guards".

Self-test proves mutations are caught and the live tracked tree is clean.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Callable, Iterable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Fragment assembly: avoids embedding a contiguous forbidden token in this file.
_K = "k"
_GUARD = "guard"
_TYPO_TAIL = "gurad"  # known transposition typo tail (joined with _K at runtime)

# User-requested variants with boundary guards (see module docstring).
FORBIDDEN_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9]){_K}\s*[-_ ]?{_GUARD}(?![A-Za-z0-9])"
    rf"|(?<![A-Za-z0-9]){_K}{_TYPO_TAIL}(?![A-Za-z0-9])"
)

# Explicit samples used only in self-test mutators (assembled at runtime so
# this tracked source file never embeds a contiguous forbidden token).
def _samples() -> tuple[str, ...]:
    return (
        "K" + "Guard",
        _K + "-" + _GUARD,
        _K + "_" + _GUARD,
        _K + " " + _GUARD,
        _K + _TYPO_TAIL,
        (_K + _GUARD).upper(),
    )

# Binary / non-text extensions skipped (cannot carry prose vocabulary claims).
SKIP_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".xz",
        ".7z",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".so",
        ".a",
        ".o",
        ".dylib",
        ".dll",
        ".exe",
        ".bin",
        ".pyc",
        ".pyo",
        ".class",
        ".jar",
        ".wasm",
        ".db",
        ".sqlite",
        ".mp4",
        ".mp3",
        ".wav",
    }
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def git_tracked_paths() -> list[pathlib.Path]:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        fail(
            "git ls-files failed — gate requires a git worktree to assert "
            f"tracked release content: {proc.stderr.decode('utf-8', 'replace')}"
        )
    out: list[pathlib.Path] = []
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8", "surrogateescape")
        path = REPO_ROOT / rel
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if not path.is_file():
            # Deleted-but-staged edge: skip missing paths.
            continue
        out.append(path)
    return out


def read_text_lossy(path: pathlib.Path) -> str | None:
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return None  # binary
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def scan_text(text: str, where: str) -> list[str]:
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if FORBIDDEN_RE.search(line):
            hits.append(f"{where}:{lineno}:{line.rstrip()[:200]}")
    return hits


def scan_paths(paths: Iterable[pathlib.Path]) -> list[str]:
    hits: list[str] = []
    for path in paths:
        text = read_text_lossy(path)
        if text is None:
            continue
        try:
            rel = path.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            rel = str(path)
        hits.extend(scan_text(text, rel))
    return hits


def check() -> None:
    paths = git_tracked_paths()
    if len(paths) < 50:
        fail(f"tracked path set unexpectedly small: {len(paths)}")
    hits = scan_paths(paths)
    if hits:
        preview = "\n".join(hits[:30])
        more = "" if len(hits) <= 30 else f"\n... +{len(hits) - 30} more"
        fail(
            "forbidden vocabulary present in tracked release content "
            f"({len(hits)} hit(s); must be 0):\n{preview}{more}"
        )
    print(
        "release_forbidden_vocabulary_gate OK: "
        f"tracked_text_files={len(paths)} forbidden_hits=0"
    )


def _expect_fail(label: str, mutator: Callable[[], None]) -> None:
    try:
        mutator()
    except GateFailure as e:
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail (false green)")


def self_test() -> None:
    samples = _samples()
    # Pattern must catch each sample variant.
    for sample in samples:
        if not FORBIDDEN_RE.search(sample):
            fail(f"pattern missed sample {sample!r}")
        if not FORBIDDEN_RE.search(f"prefix {sample} suffix"):
            fail(f"pattern missed embedded sample {sample!r}")

    # Ordinary English must not trip the gate.
    benign = (
        "clock guard成立",
        "Block guardでflag=0",
        "ok_guards = []",
        "precheck guard missing",
        "application-specific vocabulary",
    )
    for line in benign:
        if FORBIDDEN_RE.search(line):
            fail(f"false positive on benign line: {line!r}")

    def mut_inject() -> None:
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "bad.md"
            p.write_text(
                f"# note\nPublic ABI / {samples[0]} vocabulary / x\n",
                encoding="utf-8",
            )
            hits = scan_paths([p])
            if not hits:
                fail("mutator setup: inject not detected")
            fail(hits[0])

    _expect_fail("inject_product_token", mut_inject)

    def mut_typo() -> None:
        hits = scan_text(f"typo {samples[4]} in docs\n", "mut.md")
        if not hits:
            fail("mutator setup: typo form not detected")
        fail(hits[0])

    _expect_fail("typo_transposition", mut_typo)

    def mut_spaced() -> None:
        hits = scan_text(f"see {samples[3]} product\n", "mut.md")
        if not hits:
            fail("mutator setup: spaced form not detected")
        fail(hits[0])

    _expect_fail("spaced_form", mut_spaced)

    # Live tracked tree must be clean.
    check()
    print("release_forbidden_vocabulary_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: release_forbidden_vocabulary_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as e:
        print(f"release_forbidden_vocabulary_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
