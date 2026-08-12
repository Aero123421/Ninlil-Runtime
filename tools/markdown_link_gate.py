#!/usr/bin/env python3
"""Fail-closed local Markdown link checker for release-facing repository docs.

The gate deliberately validates only local file targets. Remote URLs, in-page
anchors, absolute paths captured in historical review records, and templated
targets are outside this deterministic offline check.
"""

from __future__ import annotations

import argparse
import json
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
FENCE_START = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})[^\r\n]*$")
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
LANGUAGE_POLICY_BEGIN = "<!-- ninlil-doc-language-policy-v1:begin -->"
LANGUAGE_POLICY_END = "<!-- ninlil-doc-language-policy-v1:end -->"
LANGUAGE_POLICY_SCOPE = "*.md"
LANGUAGE_POLICY_TRANSLATION_STATUS = (
    "SOURCE_LANGUAGE_RECORDED_NO_NORMATIVE_TRANSLATION"
)
LANGUAGE_POLICY_SOURCE_LANGUAGES = {"en", "ja"}


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


def _all_markdown(root: pathlib.Path) -> list[pathlib.Path]:
    """Return every Markdown file in a sealed source tree.

    Release clean-room extraction intentionally has no ``.git`` directory.
    This mode lets the same checker validate the archive payload itself instead
    of silently depending on the checkout which produced it.
    """
    return sorted(
        path
        for path in root.rglob("*.md")
        if path.is_file() and ".git" not in path.parts
    )


def _without_fenced_code(text: str) -> str:
    """Mask fenced code so regex-like examples cannot become false links."""
    output: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if fence_character is None:
            opening = FENCE_START.match(body)
            if opening is None:
                output.append(line)
                continue
            marker = opening.group(1)
            fence_character = marker[0]
            fence_length = len(marker)
        else:
            closing = re.fullmatch(
                rf"[ \t]{{0,3}}{re.escape(fence_character)}"
                rf"{{{fence_length},}}[ \t]*",
                body,
            )
            if closing is not None:
                fence_character = None
                fence_length = 0
        output.append(line[len(body) :])
    return "".join(output)


def _targets(text: str) -> list[str]:
    text = _without_fenced_code(text)
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


def _language_policy_errors(root: pathlib.Path) -> list[str]:
    """Keep every top-level docs source in one explicit language roster."""
    index = root / "docs" / "README.md"
    if not index.is_file():
        return []
    text = index.read_text(encoding="utf-8")
    if text.count(LANGUAGE_POLICY_BEGIN) != 1 or text.count(LANGUAGE_POLICY_END) != 1:
        return ["docs/README.md: language policy markers must occur exactly once"]
    middle = text.split(LANGUAGE_POLICY_BEGIN, 1)[1].split(LANGUAGE_POLICY_END, 1)[0]
    match = re.fullmatch(r"\s*```json\s*\n(?P<body>.*?)\n```\s*", middle, re.DOTALL)
    if match is None:
        return ["docs/README.md: language policy must be one live JSON fence"]
    duplicate_keys: list[str] = []

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                duplicate_keys.append(key)
            result[key] = value
        return result

    try:
        policy = json.loads(
            match.group("body"), object_pairs_hook=reject_duplicate_keys
        )
    except json.JSONDecodeError as exc:
        return [f"docs/README.md: invalid language policy JSON: {exc}"]
    if duplicate_keys:
        return [
            "docs/README.md: duplicate language policy key(s): "
            + ", ".join(sorted(set(duplicate_keys)))
        ]
    if not isinstance(policy, dict) or set(policy) != {
        "scope",
        "documents",
        "translation_status",
    }:
        return ["docs/README.md: language policy fields are not closed"]
    if policy.get("scope") != LANGUAGE_POLICY_SCOPE:
        return ["docs/README.md: language policy scope drift"]
    if (
        policy.get("translation_status")
        != LANGUAGE_POLICY_TRANSLATION_STATUS
    ):
        return ["docs/README.md: language policy translation status drift"]

    documents = policy.get("documents")
    if not isinstance(documents, dict) or not documents:
        return ["docs/README.md: language policy documents must be a non-empty object"]
    errors: list[str] = []
    for name, language in documents.items():
        if (
            not isinstance(name, str)
            or pathlib.PurePosixPath(name).name != name
            or not name.endswith(".md")
        ):
            errors.append(
                f"docs/README.md: invalid language-policy document name {name!r}"
            )
        if language not in LANGUAGE_POLICY_SOURCE_LANGUAGES:
            errors.append(
                f"docs/README.md: {name}: unsupported source language {language!r}"
            )

    actual = sorted(
        path.name
        for path in index.parent.glob(LANGUAGE_POLICY_SCOPE)
        if path.is_file()
    )
    if not actual:
        return ["docs/README.md: language policy scope matched no specifications"]
    listed = sorted(documents)
    missing = sorted(set(actual) - set(listed))
    stale = sorted(set(listed) - set(actual))
    if missing:
        errors.append(
            "docs/README.md: language policy missing document(s): "
            + ", ".join(missing)
        )
    if stale:
        errors.append(
            "docs/README.md: language policy lists absent document(s): "
            + ", ".join(stale)
        )

    numbered = sorted(path.name for path in index.parent.glob("[0-9][0-9]-*.md"))
    try:
        reading_order = text.split("## 読む順番", 1)[1].split("## 実装開始条件", 1)[0]
    except IndexError:
        return ["docs/README.md: reading-order section markers are incomplete"]
    for name in numbered:
        count = len(re.findall(rf"\]\({re.escape(name)}(?:#[^)]+)?\)", reading_order))
        if count != 1:
            errors.append(
                f"docs/README.md: language-policy document {name} "
                f"must be indexed exactly once (got {count})"
            )
    return errors


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
    errors.extend(_language_policy_errors(root))
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
            "[ref]: <docs/target.md>\n"
            "```text\n"
            "[regex](missing-inside-code.md)\n"
            "```\n",
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
        assert _all_markdown(root) == sorted([good, bad, target])

        numbered = [docs / "00-a.md", docs / "01-b.md"]
        for path in numbered:
            path.write_text(f"# {path.stem}\n", encoding="utf-8")
        index = docs / "README.md"
        policy = {
            "scope": LANGUAGE_POLICY_SCOPE,
            "documents": {
                "00-a.md": "ja",
                "01-b.md": "ja",
                "README.md": "ja",
                "bad.md": "en",
                "target.md": "en",
            },
            "translation_status": LANGUAGE_POLICY_TRANSLATION_STATUS,
        }
        index.write_text(
            "# Docs\n\n"
            f"{LANGUAGE_POLICY_BEGIN}\n"
            "```json\n"
            + json.dumps(policy, ensure_ascii=False, indent=2)
            + "\n```\n"
            f"{LANGUAGE_POLICY_END}\n\n"
            "## 読む順番\n\n"
            "[A](00-a.md)\n[B](01-b.md)\n\n"
            "## 実装開始条件\n",
            encoding="utf-8",
        )
        assert check(root, [index, *numbered]) == []

        # Source mutation: a newly added docs source must be RED until its
        # source language is explicitly entered in the central roster.
        added = docs / "02-new.md"
        added.write_text("# new\n", encoding="utf-8")
        assert any(
            "language policy missing document(s): 02-new.md" in item
            for item in check(root, [index, *numbered, added])
        )
        added.unlink()

        baseline_index = index.read_text(encoding="utf-8")
        invalid_language = baseline_index.replace(
            '"01-b.md": "ja"', '"01-b.md": "fr"', 1
        )
        assert invalid_language != baseline_index
        index.write_text(invalid_language, encoding="utf-8")
        assert any(
            "01-b.md: unsupported source language 'fr'" in item
            for item in check(root, [index, *numbered])
        )
        index.write_text(baseline_index, encoding="utf-8")

        index.write_text(
            index.read_text(encoding="utf-8").replace("[B](01-b.md)\n", ""),
            encoding="utf-8",
        )
        assert any(
            "01-b.md must be indexed exactly once" in item
            for item in check(root, [index, *numbered])
        )
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
    check_parser.add_argument(
        "--all-markdown",
        action="store_true",
        help="scan every Markdown file (for a sealed source archive without .git)",
    )
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0
    selected = _all_markdown(args.root.resolve()) if args.all_markdown else None
    errors = check(args.root, selected)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"markdown link gate: {len(errors)} error(s)", file=sys.stderr)
        return 1
    scope = "archive" if args.all_markdown else "tracked"
    print(
        "markdown link gate: "
        f"all {scope} local targets exist with exact case"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
