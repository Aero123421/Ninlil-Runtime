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
DOC_TAXONOMY_BEGIN = "<!-- ninlil-doc-taxonomy-v1:begin -->"
DOC_TAXONOMY_END = "<!-- ninlil-doc-taxonomy-v1:end -->"
DOC_TAXONOMY = (
    ("README", "../README.md"),
    ("concept", "runtime-concepts.md"),
    ("tutorial", "host-runtime-tutorial.md"),
    ("how-to", "host-runtime-sdk.md"),
    ("reference", "sdk-distribution-manifest.md"),
    ("explanation", "01-architecture.md"),
)
DOC_TAXONOMY_ROW = re.compile(
    r"^\| `(?P<category>[^`|]+)` \| "
    r"\[[^\]\n]+\]\((?P<target>[^)\s]+)\) \| [^|\n]+ \|$"
)
TUTORIAL_PATH = pathlib.Path("docs/host-runtime-tutorial.md")
TUTORIAL_BASH = (
    "cmake --version\n"
    "python3 --version\n"
    "node --version\n"
    "openssl version",
    "git clone https://github.com/Aero123421/Ninlil-Runtime.git\n"
    "cd Ninlil-Runtime",
    "cmake -S . -B build-tutorial -DCMAKE_BUILD_TYPE=Debug\n"
    "cmake --build build-tutorial \\\n"
    "  --target ninlil_v1_integration_gate_e2e_test --parallel",
    "ctest --test-dir build-tutorial \\\n"
    "  -R '^v1_integration_gate_e2e$' --output-on-failure --no-tests=error",
)


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


def _without_html_comments(text: str) -> str:
    output: list[str] = []
    cursor = 0
    while cursor < len(text):
        opening = text.find("<!--", cursor)
        closing = text.find("-->", cursor)
        if closing >= 0 and (opening < 0 or closing < opening):
            raise ValueError("unmatched Markdown HTML comment close")
        if opening < 0:
            output.append(text[cursor:])
            break
        output.append(text[cursor:opening])
        closing = text.find("-->", opening + 4)
        if closing < 0:
            raise ValueError("unterminated Markdown HTML comment")
        cursor = closing + 3
    return "".join(output)


def _top_level_marker_region(text: str, begin: str, end: str) -> str:
    """Return the live region between exact markers outside comments/fences."""
    begin_token = "NINLIL_ACTIVE_MARKER_BEGIN_7DAD0E13"
    end_token = "NINLIL_ACTIVE_MARKER_END_7DAD0E13"
    if begin_token in text or end_token in text:
        raise ValueError("reserved active-marker token occurs in Markdown")
    protected = text.replace(begin, begin_token).replace(end, end_token)
    clean = _without_html_comments(protected)
    lines = clean.splitlines(keepends=True)
    fence_character: str | None = None
    fence_length = 0
    begins: list[int] = []
    ends: list[int] = []
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        if fence_character is None:
            stripped = body.strip()
            if stripped == begin_token:
                begins.append(index)
                continue
            if stripped == end_token:
                ends.append(index)
                continue
            opening = FENCE_START.match(body)
            if opening is not None:
                marker = opening.group(1)
                fence_character = marker[0]
                fence_length = len(marker)
        elif re.fullmatch(
            rf"[ \t]{{0,3}}{re.escape(fence_character)}"
            rf"{{{fence_length},}}[ \t]*",
            body,
        ):
            fence_character = None
            fence_length = 0
    if fence_character is not None:
        raise ValueError("unterminated Markdown fence")
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise ValueError("active authority markers must occur exactly once in order")
    return "".join(lines[begins[0] + 1 : ends[0]])


def _active_fenced_blocks(text: str, language: str) -> list[str]:
    text = _without_html_comments(text)
    blocks: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    capture = False
    body_lines: list[str] = []
    for line in text.splitlines():
        if fence_character is None:
            opening = re.fullmatch(r"[ \t]{0,3}(`{3,}|~{3,})([^\r\n]*)", line)
            if opening is None:
                continue
            marker = opening.group(1)
            fence_character = marker[0]
            fence_length = len(marker)
            capture = opening.group(2).strip() == language
            body_lines = []
            continue
        closing = re.fullmatch(
            rf"[ \t]{{0,3}}{re.escape(fence_character)}"
            rf"{{{fence_length},}}[ \t]*",
            line,
        )
        if closing is not None:
            if capture:
                blocks.append("\n".join(body_lines))
            fence_character = None
            fence_length = 0
            capture = False
            body_lines = []
        elif capture:
            body_lines.append(line)
    if fence_character is not None:
        raise ValueError("unterminated Markdown fence")
    return blocks


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
    raw_text = index.read_text(encoding="utf-8")
    try:
        middle = _top_level_marker_region(
            raw_text,
            LANGUAGE_POLICY_BEGIN,
            LANGUAGE_POLICY_END,
        )
        active_text = _without_fenced_code(_without_html_comments(raw_text))
    except ValueError as exc:
        return [f"docs/README.md: {exc}"]
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
        reading_order = active_text.split("## 読む順番", 1)[1].split(
            "## 実装開始条件", 1
        )[0]
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


def _doc_taxonomy_errors(root: pathlib.Path) -> list[str]:
    """Keep the six user-facing documentation classes closed and routed."""
    index = root / "docs" / "README.md"
    if not index.is_file():
        return []
    try:
        middle = _top_level_marker_region(
            index.read_text(encoding="utf-8"),
            DOC_TAXONOMY_BEGIN,
            DOC_TAXONOMY_END,
        )
    except ValueError as exc:
        return [f"docs/README.md: {exc}"]
    lines = [line.strip() for line in middle.splitlines() if line.strip()]
    expected_header = [
        "| 類型 | 現行入口 | 用途 |",
        "| --- | --- | --- |",
    ]
    errors: list[str] = []
    if lines[:2] != expected_header:
        errors.append("docs/README.md: document taxonomy table header drift")

    parsed: list[tuple[str, str]] = []
    for line in lines[2:]:
        match = DOC_TAXONOMY_ROW.fullmatch(line)
        if match is None:
            errors.append(
                "docs/README.md: malformed document taxonomy row: " + line
            )
            continue
        parsed.append((match.group("category"), match.group("target")))

    if parsed != list(DOC_TAXONOMY):
        rendered = ", ".join(
            f"{category}={target}" for category, target in DOC_TAXONOMY
        )
        errors.append(
            "docs/README.md: document taxonomy rows must be exactly: " + rendered
        )
    return errors


def _tutorial_command_errors(root: pathlib.Path) -> list[str]:
    if not (root / "docs/README.md").is_file():
        return []
    tutorial = root / TUTORIAL_PATH
    if not tutorial.is_file():
        return [f"{TUTORIAL_PATH}: tutorial authority is missing"]
    text = tutorial.read_text(encoding="utf-8")
    try:
        blocks = _active_fenced_blocks(text, "bash")
    except ValueError as exc:
        return [f"{TUTORIAL_PATH}: {exc}"]
    if blocks != list(TUTORIAL_BASH):
        return [
            f"{TUTORIAL_PATH}: active configure/build/CTest commands must be exact"
        ]
    return []


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
    errors.extend(_doc_taxonomy_errors(root))
    errors.extend(_tutorial_command_errors(root))
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

        taxonomy_targets = {
            target_name
            for _, target_name in DOC_TAXONOMY
            if not target_name.startswith("../")
        }
        for name in taxonomy_targets:
            content = f"# {name}\n"
            if name == TUTORIAL_PATH.name:
                content += "\n" + "\n\n".join(
                    f"```bash\n{command}\n```" for command in TUTORIAL_BASH
                ) + "\n"
            (docs / name).write_text(content, encoding="utf-8")

        numbered = [
            docs / "00-a.md",
            docs / "01-b.md",
            docs / "01-architecture.md",
        ]
        for path in numbered:
            path.write_text(f"# {path.stem}\n", encoding="utf-8")
        index = docs / "README.md"
        policy_documents = {
            path.name: "ja" for path in docs.glob("*.md") if path.is_file()
        }
        policy_documents["bad.md"] = "en"
        policy_documents["target.md"] = "en"
        policy_documents["README.md"] = "ja"
        policy = {
            "scope": LANGUAGE_POLICY_SCOPE,
            "documents": policy_documents,
            "translation_status": LANGUAGE_POLICY_TRANSLATION_STATUS,
        }
        taxonomy = (
            f"{DOC_TAXONOMY_BEGIN}\n"
            "| 類型 | 現行入口 | 用途 |\n"
            "| --- | --- | --- |\n"
            + "\n".join(
                f"| `{category}` | [Entry]({target_name}) | Purpose |"
                for category, target_name in DOC_TAXONOMY
            )
            + f"\n{DOC_TAXONOMY_END}\n\n"
        )
        index.write_text(
            "# Docs\n\n"
            + taxonomy
            + f"{LANGUAGE_POLICY_BEGIN}\n"
            + "```json\n"
            + json.dumps(policy, ensure_ascii=False, indent=2)
            + "\n```\n"
            + f"{LANGUAGE_POLICY_END}\n\n"
            + "## 読む順番\n\n"
            + "[A](00-a.md)\n[B](01-b.md)\n"
            + "[Architecture](01-architecture.md)\n\n"
            + "## 実装開始条件\n",
            encoding="utf-8",
        )
        assert check(root, [index, *numbered]) == []

        baseline_index = index.read_text(encoding="utf-8")
        tutorial_row = next(
            line for line in taxonomy.splitlines() if line.startswith("| `tutorial`")
        )
        missing_class = baseline_index.replace(tutorial_row + "\n", "", 1)
        assert missing_class != baseline_index
        index.write_text(missing_class, encoding="utf-8")
        assert any(
            "document taxonomy rows must be exactly" in item
            for item in check(root, [index, *numbered])
        )

        wrong_target = baseline_index.replace(
            "(host-runtime-tutorial.md)", "(host-runtime-sdk.md)", 1
        )
        assert wrong_target != baseline_index
        index.write_text(wrong_target, encoding="utf-8")
        assert any(
            "document taxonomy rows must be exactly" in item
            for item in check(root, [index, *numbered])
        )
        index.write_text(baseline_index, encoding="utf-8")

        fenced_taxonomy = baseline_index.replace(
            DOC_TAXONOMY_BEGIN,
            "~~~~markdown\n" + DOC_TAXONOMY_BEGIN,
            1,
        ).replace(DOC_TAXONOMY_END, DOC_TAXONOMY_END + "\n~~~~", 1)
        assert fenced_taxonomy != baseline_index
        index.write_text(fenced_taxonomy, encoding="utf-8")
        assert any(
            "active authority markers must occur exactly once" in item
            for item in check(root, [index, *numbered])
        )
        index.write_text(baseline_index, encoding="utf-8")

        fenced_policy = baseline_index.replace(
            LANGUAGE_POLICY_BEGIN,
            "~~~~markdown\n" + LANGUAGE_POLICY_BEGIN,
            1,
        ).replace(LANGUAGE_POLICY_END, LANGUAGE_POLICY_END + "\n~~~~", 1)
        assert fenced_policy != baseline_index
        index.write_text(fenced_policy, encoding="utf-8")
        assert any(
            "active authority markers must occur exactly once" in item
            for item in check(root, [index, *numbered])
        )
        index.write_text(baseline_index, encoding="utf-8")

        policy_region = (
            LANGUAGE_POLICY_BEGIN
            + baseline_index.split(LANGUAGE_POLICY_BEGIN, 1)[1].split(
                LANGUAGE_POLICY_END, 1
            )[0]
            + LANGUAGE_POLICY_END
        )
        commented_policy = baseline_index.replace(
            policy_region,
            "<!--\n" + policy_region + "\n-->",
            1,
        )
        assert commented_policy != baseline_index
        index.write_text(commented_policy, encoding="utf-8")
        assert any(
            "active authority markers must occur exactly once" in item
            for item in check(root, [index, *numbered])
        )
        index.write_text(baseline_index, encoding="utf-8")

        reading_order = (
            baseline_index.split("## 読む順番", 1)[1]
            .split("## 実装開始条件", 1)[0]
        )
        commented_reading_order = baseline_index.replace(
            "## 読む順番" + reading_order,
            "## 読む順番\n\n<!--" + reading_order + "-->",
            1,
        )
        assert commented_reading_order != baseline_index
        index.write_text(commented_reading_order, encoding="utf-8")
        assert any(
            "must be indexed exactly once" in item
            for item in check(root, [index, *numbered])
        )
        index.write_text(baseline_index, encoding="utf-8")

        tutorial = docs / TUTORIAL_PATH.name
        baseline_tutorial = tutorial.read_text(encoding="utf-8")
        command_mutations = (
            baseline_tutorial.replace(
                "ninlil_v1_integration_gate_e2e_test",
                "definitely_missing_target",
                1,
            ),
            baseline_tutorial.replace(
                "^v1_integration_gate_e2e$",
                "^definitely_missing_test$",
                1,
            ),
            "````markdown\n" + baseline_tutorial + "\n````\n",
            "<!--\n" + baseline_tutorial + "\n-->\n",
        )
        for mutation in command_mutations:
            assert mutation != baseline_tutorial
            tutorial.write_text(mutation, encoding="utf-8")
            assert any(
                "active configure/build/CTest commands must be exact" in item
                for item in check(root, [index, *numbered])
            )
        tutorial.write_text(baseline_tutorial, encoding="utf-8")

        # Source mutation: a newly added docs source must be RED until its
        # source language is explicitly entered in the central roster.
        added = docs / "02-new.md"
        added.write_text("# new\n", encoding="utf-8")
        assert any(
            "language policy missing document(s): 02-new.md" in item
            for item in check(root, [index, *numbered, added])
        )
        added.unlink()

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
