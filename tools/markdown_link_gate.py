#!/usr/bin/env python3
"""Fail-closed local Markdown link checker for release-facing repository docs.

The gate deliberately validates only local file targets. Remote URLs, in-page
anchors, absolute paths captured in historical review records, and templated
targets are outside this deterministic offline check.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.parse


INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^)\s]+)")
REFERENCE_LINK = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(<[^>\n]+>|[^ \t\n]+)",
    re.MULTILINE,
)
REMOTE_SCHEMES = {
    "app",
    "data",
    "file",
    "ftp",
    "ftps",
    "http",
    "https",
    "mailto",
    "plugin",
    "ssh",
}


def _tracked_markdown(root: pathlib.Path) -> list[pathlib.Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = []
    for raw in completed.stdout.split(b"\0"):
        if raw:
            paths.append(root / os.fsdecode(raw))
    return sorted(paths)


def _targets(text: str) -> list[str]:
    found = [match.group(1) for match in INLINE_LINK.finditer(text)]
    found.extend(match.group(1) for match in REFERENCE_LINK.finditer(text))
    return found


def _local_target(raw: str) -> str | None:
    target = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
    target = urllib.parse.unquote(target)
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme.lower() in REMOTE_SCHEMES or parsed.netloc:
        return None
    path = parsed.path
    if not path or path.startswith("/") or path.startswith("#"):
        return None
    if any(marker in path for marker in ("${", "{{", "}}", "<", ">")):
        return None
    return path


def _has_exact_case(path: pathlib.Path) -> bool:
    if not path.exists():
        return False
    current = pathlib.Path(path.anchor) if path.is_absolute() else pathlib.Path()
    for part in path.parts:
        if part in ("", path.anchor):
            continue
        try:
            names = {entry.name for entry in current.iterdir()}
        except OSError:
            return False
        if part not in names:
            return False
        current /= part
    return True


def check(root: pathlib.Path, files: list[pathlib.Path] | None = None) -> list[str]:
    root = root.resolve()
    markdown = _tracked_markdown(root) if files is None else files
    errors: list[str] = []
    for source in markdown:
        try:
            text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{source.relative_to(root)}: unreadable UTF-8: {exc}")
            continue
        for raw in _targets(text):
            relative = _local_target(raw)
            if relative is None:
                continue
            candidate = (source.parent / relative).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                errors.append(
                    f"{source.relative_to(root)}: local link escapes repository: {raw}"
                )
                continue
            if not _has_exact_case(candidate):
                errors.append(
                    f"{source.relative_to(root)}: missing or case-mismatched target: {raw}"
                )
    return sorted(set(errors))


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="ninlil-markdown-link-") as temp:
        root = pathlib.Path(temp).resolve()
        docs = root / "docs"
        docs.mkdir()
        target = docs / "target.md"
        target.write_text("# Target\n", encoding="utf-8")
        good = root / "README.md"
        good.write_text(
            "[relative](docs/target.md#section)\n"
            "[remote](https://example.invalid/no-network)\n"
            "[anchor](#local)\n"
            "[ref]: <docs/target.md>\n",
            encoding="utf-8",
        )
        assert check(root, [good, target]) == []

        bad = docs / "bad.md"
        bad.write_text(
            "[missing](nope.md)\n"
            "[case](Target.md)\n"
            "[escape](../../outside.md)\n",
            encoding="utf-8",
        )
        errors = check(root, [bad])
        assert len(errors) == 3, errors
        assert any("missing or case-mismatched" in item for item in errors)
        assert any("escapes repository" in item for item in errors)
    print("markdown link gate self-test: ok")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    check_parser = sub.add_parser("check")
    check_parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
    )
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0
    errors = check(args.root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"markdown link gate: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("markdown link gate: all tracked local targets exist with exact case")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
