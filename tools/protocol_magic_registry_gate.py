#!/usr/bin/env python3
"""Fail-closed repository protocol/storage magic registry authority.

The scan intentionally treats every exact four-byte uppercase/digit literal in
machine sources as a candidate.  Every candidate must be either a registry
entry or an explicit, reasoned exclusion.  The registry file itself is outside
the scan roots so an entry cannot make itself look live.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec/protocol-magic-registry-v1.json"
PA_REQUIRED = ("NAC1", "NAR1", "NAS1")
PA_FORBIDDEN = ("NPA1", "NPS1")
MAGIC_RE = re.compile(r"[A-Z][A-Z0-9]{3}")
# This is deliberately a *representation contract*, not a single regex.  C
# wire/storage magics regularly appear as a four-character string, a C char
# array, or a u32 in either byte order.  A quoted-token-only scan leaves an
# alternate encoding outside the collision namespace.
CANDIDATE_PATTERN = "C_QUOTED_CHAR_ARRAY_U32_BE_U32_LE_V1"
QUOTED_CANDIDATE_RE = re.compile(
    r'''(?<![A-Za-z0-9_])(?:[bBuU])?["']([A-Z][A-Z0-9]{3})["']'''
)
CHAR_ARRAY_CANDIDATE_RE = re.compile(
    r"\{\s*'([A-Z])'\s*,\s*'([A-Z0-9])'\s*,\s*'([A-Z0-9])'\s*,\s*'([A-Z0-9])'\s*\}"
)
HEX_ESCAPED_CANDIDATE_RE = re.compile(
    r'''(?<![A-Za-z0-9_])(?:[bBuU])?["']((?:\\x[0-9A-Fa-f]{2}){4})["']'''
)
SHORT_QUOTED_RE = re.compile(
    r'''(?:[bBuU])?["']([A-Z0-9]{1,3})["']'''
)
U32_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:UINT32_C\s*\(\s*)?0x([0-9A-Fa-f]{8})"
    r"(?![0-9A-Fa-f])(?:[uUlL]+)?\s*\)?"
)
SCAN_ROOTS = (
    "cmake",
    "examples",
    "include",
    "ports",
    "src",
    "tests",
    "tools",
)
SCAN_EXTENSIONS = (
    ".c",
    ".cc",
    ".cmake",
    ".cpp",
    ".h",
    ".hpp",
    ".inc",
    ".js",
    ".json",
    ".mjs",
    ".py",
)
EXCLUDED_PATH_COMPONENTS = (
    ".git",
    "__pycache__",
    "_vendor",
    "build",
    "managed_components",
)
EXCLUDED_RELATIVE_PATHS: tuple[str, ...] = ()


class RegistryError(RuntimeError):
    pass


def _reject_constant(value: str) -> None:
    raise RegistryError(f"non-finite JSON number {value}")


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_strict(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"registry JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RegistryError("$: object required")
    return value


def _closed(obj: Any, keys: set[str], path: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != keys:
        raise RegistryError(f"{path}: closed keys")
    return obj


def _closed_string_list(
    value: Any,
    path: str,
    *,
    exact: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(type(item) is not str or not item for item in value)
    ):
        raise RegistryError(f"{path}: non-empty string array required")
    result = tuple(value)
    if len(set(result)) != len(result):
        raise RegistryError(f"{path}: duplicate value")
    if result != tuple(sorted(result)):
        raise RegistryError(f"{path}: canonical sorted order")
    if exact is not None and result != exact:
        raise RegistryError(f"{path}: scan boundary drift")
    return result


def _authority_path(relative: str, repository_root: Path) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise RegistryError(f"authority path {relative!r}")
    root = repository_root.resolve()
    resolved = (root / Path(*pure.parts)).resolve()
    if resolved != root and root not in resolved.parents:
        raise RegistryError(f"authority escapes repository {relative!r}")
    if not resolved.is_file():
        raise RegistryError(f"missing authority {relative}")
    return resolved


def _validated_occurrences(
    value: Any,
    path: str,
) -> tuple[tuple[str, str, int], ...]:
    """Validate a closed, canonical occurrence manifest from the registry."""

    if not isinstance(value, list) or not value:
        raise RegistryError(f"{path}: non-empty occurrence array required")
    result: list[tuple[str, str, int]] = []
    for index, raw in enumerate(value):
        row = _closed(raw, {"path", "representation", "count"}, f"{path}[{index}]")
        relative = row["path"]
        representation = row["representation"]
        count = row["count"]
        pure = PurePosixPath(relative) if type(relative) is str else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or not pure.parts
            or representation
            not in {
                "QUOTED",
                "CONCAT_QUOTED",
                "HEX_ESCAPED",
                "CHAR_ARRAY",
                "U32_BE",
                "U32_LE",
            }
            or type(count) is not int
            or count < 1
        ):
            raise RegistryError(f"{path}[{index}]: occurrence domain")
        result.append((relative, representation, count))
    if len(set(result)) != len(result) or result != sorted(result):
        raise RegistryError(f"{path}: canonical exact occurrence order")
    return tuple(result)


def _is_scanned_source(
    path: Path,
    repository_root: Path,
    extensions: tuple[str, ...],
    excluded_components: tuple[str, ...],
    excluded_relative_paths: tuple[str, ...],
) -> bool:
    if not path.is_file() or path.suffix not in extensions:
        return False
    relative = path.relative_to(repository_root).as_posix()
    if relative in excluded_relative_paths:
        return False
    return not any(
        component in excluded_components
        or ("build" in excluded_components and component.startswith("build-"))
        for component in path.parts
    )


def scan_inventory(
    repository_root: Path,
    roots: tuple[str, ...],
    extensions: tuple[str, ...],
    excluded_components: tuple[str, ...],
    excluded_relative_paths: tuple[str, ...],
) -> dict[str, tuple[tuple[str, str, int], ...]]:
    """Return exact magic occurrences, including their source representation.

    Each tuple is ``(relative path, representation, count)``.  The signed
    count makes a same-token collision in an unrelated owner *and* a second
    occurrence in an already-authorized file fail closed, without coupling
    the manifest to unrelated line movement inside a source file.
    """

    repository_root = repository_root.resolve()
    found: dict[str, list[tuple[str, str]]] = {}
    for relative_root in roots:
        scan_root = repository_root / relative_root
        if not scan_root.exists():
            raise RegistryError(f"scan root missing {relative_root}")
        paths = [scan_root] if scan_root.is_file() else scan_root.rglob("*")
        for path in paths:
            if not _is_scanned_source(
                path,
                repository_root,
                extensions,
                excluded_components,
                excluded_relative_paths,
            ):
                continue
            relative = path.relative_to(repository_root).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise RegistryError(f"scan read {relative}: {exc}") from exc
            for match in QUOTED_CANDIDATE_RE.finditer(text):
                found.setdefault(match.group(1), []).append((relative, "QUOTED"))
            for match in HEX_ESCAPED_CANDIDATE_RE.finditer(text):
                candidate = bytes.fromhex(match.group(1).replace("\\x", "")).decode(
                    "ascii", errors="ignore"
                )
                if MAGIC_RE.fullmatch(candidate) is not None:
                    found.setdefault(candidate, []).append((relative, "HEX_ESCAPED"))
            short = list(SHORT_QUOTED_RE.finditer(text))
            for start in range(len(short)):
                candidate = short[start].group(1)
                end = start
                while len(candidate) < 4 and end + 1 < len(short):
                    between = text[short[end].end() : short[end + 1].start()]
                    if between.strip() != "":
                        break
                    end += 1
                    candidate += short[end].group(1)
                if end > start and MAGIC_RE.fullmatch(candidate) is not None:
                    found.setdefault(candidate, []).append(
                        (relative, "CONCAT_QUOTED")
                    )
            for match in CHAR_ARRAY_CANDIDATE_RE.finditer(text):
                found.setdefault("".join(match.groups()), []).append(
                    (relative, "CHAR_ARRAY")
                )
            for match in U32_CANDIDATE_RE.finditer(text):
                raw = bytes.fromhex(match.group(1))
                be = raw.decode("ascii", errors="ignore")
                le = raw[::-1].decode("ascii", errors="ignore")
                if MAGIC_RE.fullmatch(be) is not None:
                    found.setdefault(be, []).append((relative, "U32_BE"))
                if MAGIC_RE.fullmatch(le) is not None and le != be:
                    found.setdefault(le, []).append((relative, "U32_LE"))
    return {
        magic: tuple(
            (relative, representation, count)
            for (relative, representation), count in sorted(
                {
                    pair: occurrences.count(pair)
                    for pair in set(occurrences)
                }.items()
            )
        )
        for magic, occurrences in sorted(found.items())
    }


def validate(
    path: Path = REGISTRY,
    *,
    repository_root: Path = ROOT,
) -> dict[str, int]:
    doc = _load_strict(path)
    root = _closed(
        doc,
        {
            "schema",
            "version",
            "scope",
            "policy",
            "domains",
            "scan",
            "entries",
            "explicit_exclusions",
            "required_production_attachment",
            "forbidden_production_attachment",
        },
        "$",
    )
    if (
        root["schema"] != "ninlil.protocol-magic-registry.v1"
        or type(root["version"]) is not int
        or root["version"] != 1
        or root["scope"] != "GLOBAL_PROTOCOL_AND_STORAGE_NAMESPACE"
    ):
        raise RegistryError("registry identity")

    policy = _closed(
        root["policy"],
        {
            "value_bytes_exact",
            "ascii_uppercase_or_digit",
            "duplicate_value_allowed",
            "transport_or_storage_partition_exempts_collision",
            "duplicate_json_keys_rejected",
            "undeclared_scanned_candidate_rejected",
            "stale_registry_entry_rejected",
            "exact_occurrence_manifest_required",
        },
        "$.policy",
    )
    if policy != {
        "value_bytes_exact": 4,
        "ascii_uppercase_or_digit": True,
        "duplicate_value_allowed": False,
        "transport_or_storage_partition_exempts_collision": False,
        "duplicate_json_keys_rejected": True,
        "undeclared_scanned_candidate_rejected": True,
        "stale_registry_entry_rejected": True,
        "exact_occurrence_manifest_required": True,
    }:
        raise RegistryError("registry policy")

    domains = _closed(
        root["domains"],
        {
            "owners",
            "artifacts",
            "statuses",
            "authorities",
            "exclusion_reasons",
        },
        "$.domains",
    )
    owners = set(_closed_string_list(domains["owners"], "$.domains.owners"))
    artifacts = set(
        _closed_string_list(domains["artifacts"], "$.domains.artifacts")
    )
    statuses = set(
        _closed_string_list(domains["statuses"], "$.domains.statuses")
    )
    authorities = set(
        _closed_string_list(domains["authorities"], "$.domains.authorities")
    )
    exclusion_reasons = set(
        _closed_string_list(
            domains["exclusion_reasons"], "$.domains.exclusion_reasons"
        )
    )
    for authority in authorities:
        _authority_path(authority, repository_root)

    scan = _closed(
        root["scan"],
        {
            "roots",
            "extensions",
            "excluded_path_components",
            "excluded_relative_paths",
            "candidate_regex",
        },
        "$.scan",
    )
    scan_roots = _closed_string_list(
        scan["roots"], "$.scan.roots", exact=SCAN_ROOTS
    )
    scan_extensions = _closed_string_list(
        scan["extensions"], "$.scan.extensions", exact=SCAN_EXTENSIONS
    )
    excluded_components = _closed_string_list(
        scan["excluded_path_components"],
        "$.scan.excluded_path_components",
        exact=EXCLUDED_PATH_COMPONENTS,
    )
    if type(scan["excluded_relative_paths"]) is not list:
        raise RegistryError("$.scan.excluded_relative_paths: array required")
    if scan["excluded_relative_paths"]:
        excluded_paths = _closed_string_list(
            scan["excluded_relative_paths"],
            "$.scan.excluded_relative_paths",
            exact=EXCLUDED_RELATIVE_PATHS,
        )
    else:
        excluded_paths = ()
        if excluded_paths != EXCLUDED_RELATIVE_PATHS:
            raise RegistryError("$.scan.excluded_relative_paths drift")
    if scan["candidate_regex"] != CANDIDATE_PATTERN:
        raise RegistryError("$.scan.candidate_regex drift")

    entries = root["entries"]
    if not isinstance(entries, list) or not entries:
        raise RegistryError("entries")
    by_magic: dict[str, dict[str, Any]] = {}
    entry_order: list[str] = []
    for index, raw in enumerate(entries):
        entry = _closed(
            raw,
            {"magic", "owner", "artifact", "status", "authority", "occurrences"},
            f"$.entries[{index}]",
        )
        magic = entry["magic"]
        if type(magic) is not str or MAGIC_RE.fullmatch(magic) is None:
            raise RegistryError(f"magic syntax {magic!r}")
        if magic in by_magic:
            raise RegistryError(f"duplicate global magic {magic}")
        if type(entry["owner"]) is not str or entry["owner"] not in owners:
            raise RegistryError(f"{magic}: owner domain")
        if type(entry["artifact"]) is not str or entry["artifact"] not in artifacts:
            raise RegistryError(f"{magic}: artifact domain")
        if type(entry["status"]) is not str or entry["status"] not in statuses:
            raise RegistryError(f"{magic}: status domain")
        if (
            type(entry["authority"]) is not str
            or entry["authority"] not in authorities
        ):
            raise RegistryError(f"{magic}: authority domain")
        _authority_path(entry["authority"], repository_root)
        entry["_occurrences"] = _validated_occurrences(
            entry["occurrences"], f"$.entries[{index}].occurrences"
        )
        by_magic[magic] = entry
        entry_order.append(magic)
    if entry_order != sorted(entry_order):
        raise RegistryError("entries: canonical magic order")

    exclusions = root["explicit_exclusions"]
    if not isinstance(exclusions, list) or not exclusions:
        raise RegistryError("explicit_exclusions")
    excluded_by_token: dict[str, str] = {}
    exclusion_order: list[str] = []
    for index, raw in enumerate(exclusions):
        exclusion = _closed(
            raw, {"token", "reason", "occurrences"}, f"$.explicit_exclusions[{index}]"
        )
        token = exclusion["token"]
        reason = exclusion["reason"]
        if type(token) is not str or MAGIC_RE.fullmatch(token) is None:
            raise RegistryError(f"exclusion token syntax {token!r}")
        if token in excluded_by_token:
            raise RegistryError(f"duplicate exclusion {token}")
        if token in by_magic:
            raise RegistryError(f"entry/exclusion collision {token}")
        if type(reason) is not str or reason not in exclusion_reasons:
            raise RegistryError(f"{token}: exclusion reason domain")
        exclusion["_occurrences"] = _validated_occurrences(
            exclusion["occurrences"],
            f"$.explicit_exclusions[{index}].occurrences",
        )
        excluded_by_token[token] = reason
        exclusion_order.append(token)
    if exclusion_order != sorted(exclusion_order):
        raise RegistryError("explicit_exclusions: canonical token order")

    required = root["required_production_attachment"]
    forbidden = root["forbidden_production_attachment"]
    if (
        type(required) is not list
        or tuple(required) != PA_REQUIRED
        or any(type(value) is not str for value in required)
    ):
        raise RegistryError("PA required list")
    if (
        type(forbidden) is not list
        or tuple(forbidden) != PA_FORBIDDEN
        or any(type(value) is not str for value in forbidden)
    ):
        raise RegistryError("PA forbidden list")
    for magic in PA_REQUIRED:
        if by_magic.get(magic, {}).get("owner") != "PRODUCTION_ATTACHMENT":
            raise RegistryError(f"PA allocation {magic}")
    for magic in PA_FORBIDDEN:
        if by_magic.get(magic, {}).get("owner") == "PRODUCTION_ATTACHMENT":
            raise RegistryError(f"forbidden PA allocation {magic}")
        if by_magic.get(magic, {}).get("owner") != "MULTI_PARENT":
            raise RegistryError(f"reserved owner {magic}")

    inventory = scan_inventory(
        repository_root,
        scan_roots,
        scan_extensions,
        excluded_components,
        excluded_paths,
    )
    discovered = set(inventory)
    registered = set(by_magic)
    explicitly_excluded = set(excluded_by_token)
    undeclared = sorted(discovered - registered - explicitly_excluded)
    if undeclared:
        details = ", ".join(
            f"{magic}@{inventory[magic][0]}" for magic in undeclared[:12]
        )
        raise RegistryError(f"undeclared scanned candidate(s): {details}")
    stale = sorted(registered - discovered)
    if stale:
        raise RegistryError(f"stale registry entry(s): {', '.join(stale)}")
    stale_exclusions = sorted(explicitly_excluded - discovered)
    if stale_exclusions:
        raise RegistryError(
            f"stale explicit exclusion(s): {', '.join(stale_exclusions)}"
        )
    for magic, entry in by_magic.items():
        if entry["_occurrences"] != inventory[magic]:
            raise RegistryError(f"exact occurrence/owner collision {magic}")
    for token, raw in zip(exclusion_order, exclusions, strict=True):
        # `exclusions` is the raw list and remains in canonical token order.
        if raw["_occurrences"] != inventory[token]:
            raise RegistryError(f"exact exclusion occurrence collision {token}")
    return {
        "entries": len(registered),
        "exclusions": len(explicitly_excluded),
        "candidates": len(discovered),
    }


def _mutation_repository(destination: Path, document: dict[str, Any]) -> Path:
    """Copy the complete scan authority into a disposable repository root."""

    for relative_root in SCAN_ROOTS:
        source_root = ROOT / relative_root
        target_root = destination / relative_root
        target_root.mkdir(parents=True, exist_ok=True)
        paths = [source_root] if source_root.is_file() else source_root.rglob("*")
        for source in paths:
            if not _is_scanned_source(
                source,
                ROOT,
                SCAN_EXTENSIONS,
                EXCLUDED_PATH_COMPONENTS,
                EXCLUDED_RELATIVE_PATHS,
            ):
                continue
            target = destination / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    for authority in document["domains"]["authorities"]:
        source = _authority_path(authority, ROOT)
        target = destination / authority
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    registry = destination / "spec" / REGISTRY.name
    registry.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REGISTRY, registry)
    return registry


def _expect_rejected_document(
    document: dict[str, Any], label: str, repository_root: Path, registry: Path
) -> None:
    shutil.copy2(REGISTRY, registry)
    registry.write_text(
        json.dumps(document, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    try:
        validate(registry, repository_root=repository_root)
    except RegistryError:
        return
    raise RegistryError(f"mutation accepted: {label}")


def _expect_rejected_raw(
    raw: str, label: str, repository_root: Path, registry: Path
) -> None:
    shutil.copy2(REGISTRY, registry)
    registry.write_text(raw, encoding="utf-8")
    try:
        validate(registry, repository_root=repository_root)
    except RegistryError:
        return
    raise RegistryError(f"mutation accepted: {label}")


def _expect_rejected_repository_source(
    source: str, label: str, repository_root: Path, registry: Path
) -> None:
    shutil.copy2(REGISTRY, registry)
    candidate_path = repository_root / "tools" / ".magic_registry_mutant.c"
    candidate_path.write_text(source, encoding="utf-8")
    try:
        try:
            validate(registry, repository_root=repository_root)
        except RegistryError:
            return
        raise RegistryError(f"mutation accepted: {label}")
    finally:
        candidate_path.unlink(missing_ok=True)


def _self_test(repository_root: Path, registry: Path) -> int:
    doc = _load_strict(REGISTRY)
    mutations = 0

    duplicate = copy.deepcopy(doc)
    duplicate["entries"].append(dict(duplicate["entries"][0]))
    _expect_rejected_document(
        duplicate, "duplicate magic collision", repository_root, registry
    )
    mutations += 1

    stolen = copy.deepcopy(doc)
    next(entry for entry in stolen["entries"] if entry["magic"] == "NPA1")[
        "owner"
    ] = "PRODUCTION_ATTACHMENT"
    _expect_rejected_document(
        stolen, "reserved magic stolen", repository_root, registry
    )
    mutations += 1

    missing_required = copy.deepcopy(doc)
    missing_required["entries"] = [
        entry
        for entry in missing_required["entries"]
        if entry["magic"] != "NAR1"
    ]
    _expect_rejected_document(
        missing_required, "required PA entry missing", repository_root, registry
    )
    mutations += 1

    missing_scanned = copy.deepcopy(doc)
    missing_scanned["entries"] = [
        entry
        for entry in missing_scanned["entries"]
        if entry["magic"] != "NLR1"
    ]
    _expect_rejected_document(
        missing_scanned, "scanned entry missing", repository_root, registry
    )
    mutations += 1

    unknown_status = copy.deepcopy(doc)
    unknown_status["entries"][0]["status"] = "UNKNOWN_PROMOTED"
    _expect_rejected_document(
        unknown_status, "unknown status", repository_root, registry
    )
    mutations += 1

    bool_artifact = copy.deepcopy(doc)
    bool_artifact["entries"][0]["artifact"] = False
    _expect_rejected_document(
        bool_artifact, "boolean artifact", repository_root, registry
    )
    mutations += 1

    unknown_owner = copy.deepcopy(doc)
    unknown_owner["entries"][0]["owner"] = "UNKNOWN_OWNER"
    _expect_rejected_document(
        unknown_owner, "unknown owner", repository_root, registry
    )
    mutations += 1

    unknown_authority = copy.deepcopy(doc)
    unknown_authority["entries"][0]["authority"] = "docs/unknown-authority.md"
    _expect_rejected_document(
        unknown_authority, "unknown authority", repository_root, registry
    )
    mutations += 1

    overlap = copy.deepcopy(doc)
    overlap["explicit_exclusions"].append(
        {
            "token": overlap["entries"][0]["magic"],
            "reason": overlap["domains"]["exclusion_reasons"][0],
        }
    )
    overlap["explicit_exclusions"].sort(key=lambda row: row["token"])
    _expect_rejected_document(
        overlap, "entry exclusion overlap", repository_root, registry
    )
    mutations += 1

    duplicate_exclusion = copy.deepcopy(doc)
    duplicate_exclusion["explicit_exclusions"].append(
        dict(duplicate_exclusion["explicit_exclusions"][0])
    )
    _expect_rejected_document(
        duplicate_exclusion, "duplicate exclusion", repository_root, registry
    )
    mutations += 1

    stale = copy.deepcopy(doc)
    stale_magic = "ZZ" + "91"
    stale["entries"].append(
        {
            "magic": stale_magic,
            "owner": stale["domains"]["owners"][0],
            "artifact": stale["domains"]["artifacts"][0],
            "status": stale["domains"]["statuses"][0],
            "authority": stale["domains"]["authorities"][0],
        }
    )
    stale["entries"].sort(key=lambda row: row["magic"])
    _expect_rejected_document(
        stale, "stale registry entry", repository_root, registry
    )
    mutations += 1

    weakened_scan = copy.deepcopy(doc)
    weakened_scan["scan"]["roots"] = weakened_scan["scan"]["roots"][1:]
    _expect_rejected_document(
        weakened_scan, "weakened scan roots", repository_root, registry
    )
    mutations += 1

    raw = REGISTRY.read_text(encoding="utf-8")
    needle = '"status": "PROPOSED",'
    if needle not in raw:
        raise RegistryError("duplicate-key mutation anchor")
    duplicate_key_raw = raw.replace(
        needle,
        needle + '\n      "status": "PROPOSED",',
        1,
    )
    _expect_rejected_raw(
        duplicate_key_raw, "duplicate JSON status key", repository_root, registry
    )
    mutations += 1

    sentinel_prefix = "ZZ"
    sentinel_quoted = sentinel_prefix + "92"
    sentinel_be = int.from_bytes((sentinel_prefix + "94").encode("ascii"), "big")
    sentinel_le = int.from_bytes((sentinel_prefix + "95").encode("ascii"), "little")
    sentinel_hex = "".join(
        f"\\x{byte:02x}" for byte in (sentinel_prefix + "96").encode("ascii")
    )
    for source, label in (
        (f'const char *candidate = "{sentinel_quoted}";\n', "undeclared quoted magic"),
        (
            "const char candidate[4] = "
            f"{{'{sentinel_prefix[0]}','{sentinel_prefix[1]}','9','3'}};\n",
            "char-array magic",
        ),
        (f"const unsigned candidate = 0x{sentinel_be:08x}u;\n", "u32 big-endian magic"),
        (f"const unsigned candidate = 0x{sentinel_le:08x}u;\n", "u32 little-endian magic"),
        (f'const char *candidate = "{sentinel_hex}";\n', "hex-escaped magic"),
        (
            f'const char *candidate = "{sentinel_prefix}" "97";\n',
            "concatenated magic",
        ),
        (
            f'const char *unrelated_owner = "{PA_REQUIRED[0]}";\n',
            "registered magic owner/path collision",
        ),
    ):
        _expect_rejected_repository_source(source, label, repository_root, registry)
        mutations += 1

    return mutations


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="magic_registry_mutant_") as directory:
        repository_root = Path(directory)
        registry = _mutation_repository(repository_root, _load_strict(REGISTRY))
        return _self_test(repository_root, registry)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    mutations = self_test() if args.self_test else 0
    stats = validate()
    print(
        "protocol magic registry OK "
        f"entries={stats['entries']} exclusions={stats['exclusions']} "
        f"candidates={stats['candidates']} mutations={mutations}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
