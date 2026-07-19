#!/usr/bin/env python3
"""R7 test-only crypto vector freshness and pin gate.

This gate executes the Host C bridge without skips.  It does not claim ESP
execution, HIL, or R7 completion.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import pathlib
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]
ORACLE = REPO / "tools" / "r7_radio_wire_oracle.py"
PIN_TOOL = REPO / "tools" / "r7_kat_pin.py"
JSON_FIXTURE = REPO / "tests" / "radio" / "private" / "r7_crypto_vectors.json"
HEADER_FIXTURE = REPO / "tests" / "radio" / "private" / "r7_crypto_vectors.gen.h"
BRIDGE = REPO / "tests" / "radio" / "r7_crypto_vectors_bridge_test.c"
PORTABLE_C = REPO / "src" / "radio" / "r7_crypto_portable.c"
NONCE_C = REPO / "src" / "radio" / "r7_crypto_nonce.c"
OPENSSL_C = REPO / "src" / "radio" / "r7_crypto_openssl3.c"

# SHA-256 over a domain-separated concatenation of the canonical JSON and
# generated private header.  Refresh only with intentional vector review.
PINNED_ARTIFACT_SHA256 = "6efef6dc99fb8462a38e058c50dfea445d8e22d6cfe22cfb19b8d6c9fb7a0de9"
PINNED_BRIDGE_SOURCE_SHA256 = "83a6dd1b8f67f66a6bb641540c46e2d12de11997d0b077ba1ac26c8f9a57873d"

EXPECTED_BRIDGE_OUTPUT = (
    "r7_crypto_vectors_bridge OK total=37 aead=22 sha256=3 hkdf=8 "
    "binding=2 nonce=2 raw=6 portable=29 helper=2 operations=67\n"
)

ALLOWED_IMPORTS = frozenset(
    (
        "argparse",
        "ast",
        "hashlib",
        "hmac",
        "json",
        "os",
        "pathlib",
        "py_compile",
        "re",
        "shutil",
        "subprocess",
        "sys",
        "tempfile",
        "typing",
    )
)
KINDS = ("aead", "sha256", "hkdf", "binding", "nonce")
REQUIRED_IDS = frozenset(
    (
        "gcm_nist_empty",
        "gcm_nist_one_block",
        "gcm_nist_aad_nonblock",
        "gcm_nist_one_block_bad_tag",
        "hkdf_rfc5869_a.1",
        "hkdf_rfc5869_a.2",
        "sha256_empty",
        "sha256_abc",
        "sha256_multiblock",
        "r6_hop_binding",
        "r6_e2e_binding",
        "r6_schedule_hop_data_key",
        "r6_schedule_hop_data_iv",
        "r6_schedule_hop_ack_key",
        "r6_schedule_hop_ack_iv",
        "r6_schedule_e2e_key",
        "r6_schedule_e2e_iv",
        "r7_nonce_counter_1",
        "r7_nonce_counter_uint64_max_minus_1",
    )
)


def run(
    command: list[str],
    *,
    cwd: pathlib.Path = REPO,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    merged_env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged_env.update(env)
    return subprocess.run(
        command,
        cwd=str(cwd),
        env=merged_env,
        text=True,
        capture_output=True,
        check=False,
    )


def artifact_digest(json_bytes: bytes, header_bytes: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(b"ninlil-r7-json\x00")
    digest.update(json_bytes)
    digest.update(b"ninlil-r7-header\x00")
    digest.update(header_bytes)
    return digest.hexdigest()


def locate_openssl_prefix() -> pathlib.Path | None:
    candidates: list[pathlib.Path] = []
    configured = os.environ.get("NINLIL_R7_OPENSSL_PREFIX")
    if configured:
        candidates.append(pathlib.Path(configured))
    candidates.extend(
        (
            pathlib.Path("/opt/homebrew/opt/openssl@3"),
            pathlib.Path("/usr/local/opt/openssl@3"),
            pathlib.Path("/usr"),
        )
    )
    for prefix in candidates:
        if (prefix / "include" / "openssl" / "evp.h").is_file() and (
            (prefix / "lib").is_dir() or (prefix / "lib64").is_dir()
        ):
            return prefix
    return None


def compile_bridge(
    source: pathlib.Path,
    output: pathlib.Path,
    *,
    sanitize: bool,
) -> subprocess.CompletedProcess[str]:
    compiler = os.environ.get("CC") or shutil.which("clang") or "clang"
    prefix = locate_openssl_prefix()
    if prefix is None:
        return subprocess.CompletedProcess(
            [compiler], 127, "", "OpenSSL 3 development prefix not found"
        )
    libdir = prefix / "lib"
    if not libdir.is_dir():
        libdir = prefix / "lib64"
    command = [
        compiler,
        "-std=c11",
        "-O1" if sanitize else "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wvla",
        "-pedantic",
    ]
    if sanitize:
        command.extend(
            ("-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined")
        )
    command.extend(
        (
            f"-I{prefix / 'include'}",
            f"-I{REPO / 'src' / 'radio'}",
            str(PORTABLE_C),
            str(NONCE_C),
            str(OPENSSL_C),
            str(source),
            f"-L{libdir}",
            f"-Wl,-rpath,{libdir}",
            "-lcrypto",
            "-o",
            str(output),
        )
    )
    return run(command)


def execute_bridge(binary: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return run(
        [str(binary)],
        env={
            "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        },
    )


def check_bridge_execution() -> list[str]:
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="r7-bridge-") as td:
        directory = pathlib.Path(td)
        for name, sanitize in (("release", False), ("san", True)):
            binary = directory / f"bridge-{name}"
            compiled = compile_bridge(BRIDGE, binary, sanitize=sanitize)
            if compiled.returncode != 0:
                errors.append(
                    f"bridge {name} compile failed: {compiled.stderr or compiled.stdout}"
                )
                continue
            executed = execute_bridge(binary)
            if executed.returncode != 0:
                errors.append(
                    f"bridge {name} execution failed: "
                    f"{executed.stderr or executed.stdout}"
                )
            elif executed.stdout != EXPECTED_BRIDGE_OUTPUT or executed.stderr:
                errors.append(
                    f"bridge {name} output mismatch stdout={executed.stdout!r} "
                    f"stderr={executed.stderr!r}"
                )
    return errors


def canonical_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def imported_roots(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def check_stdlib_only() -> list[str]:
    errors: list[str] = []
    for path in (ORACLE, PIN_TOOL):
        roots = imported_roots(path)
        unexpected = sorted(roots - ALLOWED_IMPORTS - {"__future__"})
        if unexpected:
            errors.append(
                f"{path.name}: non-stdlib/unapproved imports: {', '.join(unexpected)}"
            )
    oracle_text = ORACLE.read_text(encoding="utf-8").lower()
    for forbidden in (
        "import cryptography",
        "from cryptography",
        "import openssl",
        "from openssl",
    ):
        if forbidden in oracle_text:
            errors.append(f"oracle contains forbidden dependency/reference: {forbidden}")
    return errors


def check_bridge_source_contract() -> list[str]:
    errors: list[str] = []
    text = BRIDGE.read_text(encoding="utf-8")
    if re.search(r"\b(malloc|calloc|realloc|free)\s*\(", text):
        errors.append("bridge heap allocation is forbidden")
    if "NINLIL_R7_CRYPTO_TEST_BUILD" in text:
        errors.append("bridge must execute production source surface")
    for marker in (
        "NINLIL_R7_TEST_VECTOR_COUNT == 37u",
        "NINLIL_R7_BRIDGE_EXPECTED_OPERATIONS ((size_t)67u)",
        "unknown AEAD surface",
        "unknown HKDF surface",
        "unknown SHA surface",
        "unknown nonce surface",
        "duplicate execution",
        "exact execution counters",
    ):
        if marker not in text:
            errors.append(f"bridge contract marker missing: {marker}")
    return errors


def validate_hex(row_id: str, field: str, value: Any) -> list[str]:
    if not isinstance(value, str):
        return [f"{row_id}.{field}: must be a string"]
    if value != value.lower() or len(value) % 2 != 0:
        return [f"{row_id}.{field}: must be even lowercase hex"]
    try:
        bytes.fromhex(value)
    except ValueError:
        return [f"{row_id}.{field}: invalid hex"]
    return []


def validate_json_document(
    document: Any, original_bytes: bytes | None = None
) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["json root must be an object"]
    if document.get("artifact") != "ninlil_r7_crypto_vectors":
        errors.append("artifact identity mismatch")
    if document.get("schema_version") != 1:
        errors.append("schema version mismatch")
    vectors = document.get("vectors")
    if not isinstance(vectors, list):
        return errors + ["vectors must be an array"]
    if document.get("vector_count") != len(vectors):
        errors.append("json vector_count mismatch")
    bridge = document.get("c_bridge")
    if not isinstance(bridge, dict):
        errors.append("c_bridge metadata missing")
    else:
        if bridge.get("implemented") is not True:
            errors.append("implemented c bridge metadata missing")
        if bridge.get("status") != "implemented":
            errors.append("c bridge status changed")
        if bridge.get("skip_allowed") is not False:
            errors.append("c bridge skip must be forbidden")
        if bridge.get("required_vector_count") != len(vectors):
            errors.append("c bridge required vector count mismatch")
    ids: list[str] = []
    kind_counts = {kind: 0 for kind in KINDS}
    hex_fields = {
        "aead": ("key", "nonce", "aad", "plaintext", "ciphertext", "tag"),
        "sha256": ("message", "digest"),
        "hkdf": ("salt", "ikm", "info", "prk", "okm"),
        "binding": ("input", "digest"),
        "nonce": ("static_iv", "counter", "nonce"),
    }
    for index, row in enumerate(vectors):
        if not isinstance(row, dict):
            errors.append(f"vector {index}: must be an object")
            continue
        row_id = row.get("id")
        kind = row.get("kind")
        if not isinstance(row_id, str) or not row_id:
            errors.append(f"vector {index}: invalid id")
            continue
        ids.append(row_id)
        if kind not in kind_counts:
            errors.append(f"{row_id}: invalid kind")
            continue
        kind_counts[kind] += 1
        if row.get("surface") not in (
            "raw_adapter",
            "portable_wrapper",
            "portable_helper",
        ):
            errors.append(f"{row_id}: invalid execution surface")
        for field in hex_fields[kind]:
            errors.extend(validate_hex(row_id, field, row.get(field)))
        if kind == "aead" and row.get("expect") not in ("ok", "auth_failed"):
            errors.append(f"{row_id}: invalid aead expectation")
        if kind == "hkdf":
            okm = row.get("okm")
            if not isinstance(okm, str) or row.get("okm_len") != len(okm) // 2:
                errors.append(f"{row_id}: hkdf okm_len mismatch")
    if len(ids) != len(set(ids)):
        errors.append("duplicate vector ids")
    if ids != sorted(ids):
        errors.append("vector ids are not stable-sorted")
    missing = sorted(REQUIRED_IDS - set(ids))
    if missing:
        errors.append(f"required vector ids missing: {', '.join(missing)}")
    for body_len in (0, 1, 15, 16, 17, 220):
        for aad_len in (0, 1, 19):
            vector_id = f"r7_gcm_body_{body_len}_aad_{aad_len}"
            if vector_id not in ids:
                errors.append(f"r7 boundary vector missing: {vector_id}")
    bad_rows = [row for row in vectors if row.get("expect") == "auth_failed"]
    if len(bad_rows) != 1 or bad_rows[0].get("id") != "gcm_nist_one_block_bad_tag":
        errors.append("bad-tag vector catalog mismatch")
    if kind_counts["aead"] != 22:
        errors.append(f"aead vector count mismatch: {kind_counts['aead']}")
    if kind_counts["hkdf"] != 8:
        errors.append(f"hkdf vector count mismatch: {kind_counts['hkdf']}")
    exact_kind_counts = {
        "aead": 22,
        "sha256": 3,
        "hkdf": 8,
        "binding": 2,
        "nonce": 2,
    }
    if kind_counts != exact_kind_counts:
        errors.append(f"vector kind catalog mismatch: {kind_counts}")
    rfc_lengths = {
        row["id"]: row.get("okm_len")
        for row in vectors
        if row.get("id") in ("hkdf_rfc5869_a.1", "hkdf_rfc5869_a.2")
    }
    if rfc_lengths != {"hkdf_rfc5869_a.1": 42, "hkdf_rfc5869_a.2": 82}:
        errors.append(f"rfc5869 okm length catalog mismatch: {rfc_lengths}")
    if original_bytes is not None:
        try:
            generated = canonical_json(document)
        except (TypeError, ValueError, UnicodeError) as exc:
            errors.append(f"json canonicalization failed: {exc}")
        else:
            if original_bytes != generated:
                errors.append("committed json is not canonical byte-exact")
            if original_bytes != original_bytes.lower():
                errors.append("committed json is not lowercase")
    return errors


def macro_count(header_text: str, kind: str | None = None) -> int | None:
    name = (
        "NINLIL_R7_TEST_VECTOR_COUNT"
        if kind is None
        else f"NINLIL_R7_{kind.upper()}_VECTOR_COUNT"
    )
    match = re.search(rf"^#define {name} ([0-9]+)u$", header_text, re.MULTILINE)
    return int(match.group(1)) if match else None


def validate_header(header_bytes: bytes, document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        text = header_bytes.decode("ascii")
    except UnicodeDecodeError:
        return ["header must be ascii"]
    vectors = document["vectors"]
    if macro_count(text) != len(vectors):
        errors.append("header total vector count mismatch")
    for kind in KINDS:
        expected = sum(row["kind"] == kind for row in vectors)
        if macro_count(text, kind) != expected:
            errors.append(f"header {kind} vector count mismatch")
    json_digest = hashlib.sha256(canonical_json(document)).hexdigest()
    if f'#define NINLIL_R7_VECTOR_JSON_SHA256 "{json_digest}"' not in text:
        errors.append("header json digest mismatch")
    for row in vectors:
        if text.count(f'"{row["id"]}"') != 1:
            errors.append(f"header id count mismatch: {row['id']}")
    if "c bridge status: implemented" not in text:
        errors.append("header c bridge status missing")
    return errors


def generate_in(directory: pathlib.Path, seed: str) -> tuple[bytes, bytes, list[str]]:
    json_path = directory / "vectors.json"
    header_path = directory / "vectors.gen.h"
    result = run(
        [
            sys.executable,
            str(ORACLE),
            "generate",
            "--json",
            str(json_path),
            "--header",
            str(header_path),
        ],
        cwd=directory,
        env={"PYTHONHASHSEED": seed},
    )
    errors: list[str] = []
    if result.returncode != 0:
        errors.append(
            f"oracle generation failed seed={seed}: {result.stderr or result.stdout}"
        )
        return b"", b"", errors
    return json_path.read_bytes(), header_path.read_bytes(), errors


def oracle_verify(path: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return run([sys.executable, str(ORACLE), "verify-json", "--json", str(path)])


def collect_errors() -> tuple[list[str], int, str]:
    errors: list[str] = []
    for path in (
        ORACLE,
        PIN_TOOL,
        JSON_FIXTURE,
        HEADER_FIXTURE,
        BRIDGE,
        PORTABLE_C,
        NONCE_C,
        OPENSSL_C,
    ):
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(REPO)}")
    if errors:
        return errors, 0, ""
    errors.extend(check_stdlib_only())
    errors.extend(check_bridge_source_contract())
    with tempfile.TemporaryDirectory(prefix="r7-pycompile-") as td:
        compile_dir = pathlib.Path(td)
        for path in (ORACLE, PIN_TOOL):
            try:
                py_compile.compile(
                    str(path),
                    cfile=str(compile_dir / f"{path.stem}.pyc"),
                    doraise=True,
                )
            except py_compile.PyCompileError as exc:
                errors.append(f"py_compile {path.name}: {exc}")
    oracle_self = run([sys.executable, str(ORACLE), "self-test"])
    if oracle_self.returncode != 0:
        errors.append(f"oracle self-test failed: {oracle_self.stderr or oracle_self.stdout}")
    with tempfile.TemporaryDirectory(prefix="r7-gen-a-") as a_dir, tempfile.TemporaryDirectory(
        prefix="r7-gen-b-"
    ) as b_dir:
        json_a, header_a, gen_errors_a = generate_in(pathlib.Path(a_dir), "17")
        json_b, header_b, gen_errors_b = generate_in(pathlib.Path(b_dir), "9301")
        errors.extend(gen_errors_a)
        errors.extend(gen_errors_b)
    if (json_a, header_a) != (json_b, header_b):
        errors.append("two temp dirs/hash seeds did not generate byte-identical artifacts")
    committed_json = JSON_FIXTURE.read_bytes()
    committed_header = HEADER_FIXTURE.read_bytes()
    if committed_json != json_a:
        errors.append("committed json fixture is stale")
    if committed_header != header_a:
        errors.append("committed generated header is stale")
    try:
        document = json.loads(committed_json.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"committed json parse failed: {exc}")
        return errors, 0, ""
    errors.extend(validate_json_document(document, committed_json))
    errors.extend(validate_header(committed_header, document))
    digest = artifact_digest(committed_json, committed_header)
    if digest != PINNED_ARTIFACT_SHA256:
        errors.append(
            f"artifact sha256 mismatch got={digest} pin={PINNED_ARTIFACT_SHA256}"
        )
    verify = oracle_verify(JSON_FIXTURE)
    if verify.returncode != 0:
        errors.append(f"oracle rejected committed json: {verify.stderr or verify.stdout}")
    bridge_source_digest = hashlib.sha256(BRIDGE.read_bytes()).hexdigest()
    if bridge_source_digest != PINNED_BRIDGE_SOURCE_SHA256:
        errors.append(
            "bridge source sha256 mismatch "
            f"got={bridge_source_digest} pin={PINNED_BRIDGE_SOURCE_SHA256}"
        )
    errors.extend(check_bridge_execution())
    return errors, len(document["vectors"]), digest


def replace_once(text: str, old: str, new: str, label: str) -> tuple[str, str | None]:
    if text.count(old) != 1:
        return text, f"{label}: mutation needle count is {text.count(old)}, want 1"
    return text.replace(old, new, 1), None


def binary_mutation_must_fail(
    label: str,
    source_text: str,
    header_bytes: bytes,
) -> list[str]:
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix=f"r7-mut-{label}-") as td:
        directory = pathlib.Path(td)
        private = directory / "private"
        private.mkdir()
        source = directory / BRIDGE.name
        header = private / HEADER_FIXTURE.name
        source.write_text(source_text, encoding="utf-8")
        header.write_bytes(header_bytes)
        binary = directory / "bridge-mutated"
        compiled = compile_bridge(source, binary, sanitize=False)
        if compiled.returncode != 0:
            errors.append(
                f"{label}: mutated bridge must compile before red execution: "
                f"{compiled.stderr or compiled.stdout}"
            )
            return errors
        executed = execute_bridge(binary)
        if executed.returncode == 0:
            errors.append(f"{label}: mutated bridge produced a false green")
    return errors


def mutation_self_tests() -> list[str]:
    errors: list[str] = []
    committed_json = JSON_FIXTURE.read_bytes()
    committed_header = HEADER_FIXTURE.read_bytes()
    document = json.loads(committed_json.decode("ascii"))

    artifact_mutation = bytearray(committed_json)
    position = artifact_mutation.find(b"0011223344556677")
    if position < 0:
        errors.append("artifact mutation setup string missing")
    else:
        artifact_mutation[position] = ord("1")
        if bytes(artifact_mutation) == committed_json:
            errors.append("artifact mutation was not applied")
        if artifact_digest(bytes(artifact_mutation), committed_header) == PINNED_ARTIFACT_SHA256:
            errors.append("artifact mutation escaped pin gate")

    bad_pin = ("0" if PINNED_ARTIFACT_SHA256[0] != "0" else "1") + PINNED_ARTIFACT_SHA256[1:]
    if artifact_digest(committed_json, committed_header) == bad_pin:
        errors.append("pin mutation escaped digest gate")

    bridge_digest = hashlib.sha256(BRIDGE.read_bytes()).hexdigest()
    bad_bridge_pin = ("0" if bridge_digest[0] != "0" else "1") + bridge_digest[1:]
    if bridge_digest == bad_bridge_pin:
        errors.append("bridge source pin mutation escaped digest gate")

    count_mutation = json.loads(committed_json)
    count_mutation["vector_count"] += 1
    if not validate_json_document(count_mutation):
        errors.append("count mutation escaped json gate")

    skip_mutation = json.loads(committed_json)
    skip_mutation["c_bridge"]["skip_allowed"] = True
    if not validate_json_document(skip_mutation):
        errors.append("c bridge skip mutation escaped json gate")

    header_mutation = committed_header.replace(
        f"NINLIL_R7_TEST_VECTOR_COUNT {len(document['vectors'])}u".encode("ascii"),
        f"NINLIL_R7_TEST_VECTOR_COUNT {len(document['vectors']) + 1}u".encode("ascii"),
        1,
    )
    if not validate_header(header_mutation, document):
        errors.append("header vector-count mutation escaped header gate")

    bad_tag_mutation = json.loads(committed_json)
    good = next(
        row for row in bad_tag_mutation["vectors"] if row["id"] == "gcm_nist_one_block"
    )
    bad = next(
        row
        for row in bad_tag_mutation["vectors"]
        if row["id"] == "gcm_nist_one_block_bad_tag"
    )
    bad["tag"] = good["tag"]
    with tempfile.TemporaryDirectory(prefix="r7-bad-tag-mut-") as td:
        path = pathlib.Path(td) / "mutated.json"
        path.write_bytes(canonical_json(bad_tag_mutation))
        result = oracle_verify(path)
    if result.returncode == 0:
        errors.append("bad-tag mutation escaped independent oracle gate")

    source_text = BRIDGE.read_text(encoding="utf-8")
    mutated, error = replace_once(
        source_text,
        "for (i = 0u; i < NINLIL_R7_AEAD_VECTOR_COUNT; i++) {",
        "for (i = 0u; i + 1u < NINLIL_R7_AEAD_VECTOR_COUNT; i++) {",
        "early-return",
    )
    if error:
        errors.append(error)
    else:
        errors.extend(binary_mutation_must_fail("early-return", mutated, committed_header))

    counter_needle = (
        "        counters.total++;\n"
        "    }\n"
        "    for (i = 0u; i < NINLIL_R7_SHA256_VECTOR_COUNT; i++) {"
    )
    counter_replacement = (
        "        counters.total += 2u;\n"
        "    }\n"
        "    for (i = 0u; i < NINLIL_R7_SHA256_VECTOR_COUNT; i++) {"
    )
    mutated, error = replace_once(
        source_text, counter_needle, counter_replacement, "execution-counter"
    )
    if error:
        errors.append(error)
    else:
        errors.extend(
            binary_mutation_must_fail("execution-counter", mutated, committed_header)
        )

    skip_needle = "    if (vector->expect_ok != 0u) {"
    skip_replacement = (
        "    if (is_raw && vector->expect_ok != 0u) {\n"
        "        counters->aead++;\n"
        "        counters->raw_adapter++;\n"
        "        return 1;\n"
        "    }\n"
        "    if (vector->expect_ok != 0u) {"
    )
    mutated, error = replace_once(
        source_text, skip_needle, skip_replacement, "surface-skip"
    )
    if error:
        errors.append(error)
    else:
        errors.extend(binary_mutation_must_fail("surface-skip", mutated, committed_header))

    auth_needle = ") != NINLIL_R7_CRYPTO_RAW_AUTH_FAILED) {"
    auth_replacement = ") != NINLIL_R7_CRYPTO_RAW_OK) {"
    mutated, error = replace_once(
        source_text, auth_needle, auth_replacement, "bad-tag-auth"
    )
    if error:
        errors.append(error)
    else:
        errors.extend(binary_mutation_must_fail("bad-tag-auth", mutated, committed_header))

    surface_header = committed_header.replace(
        b'"raw_adapter"', b'"unknown_surface"', 1
    )
    if surface_header == committed_header:
        errors.append("unknown-surface mutation setup failed")
    else:
        errors.extend(
            binary_mutation_must_fail("unknown-surface", source_text, surface_header)
        )

    tag_header = committed_header.replace(
        b"aa6e47d42cec13bdf53a67b21257bddf",
        b"ab6e47d42cec13bdf53a67b21257bddf",
        1,
    )
    if tag_header == committed_header:
        errors.append("bad-tag binary mutation setup failed")
    else:
        errors.extend(binary_mutation_must_fail("bad-tag-vector", source_text, tag_header))
    return errors


def run_check() -> int:
    errors, count, digest = collect_errors()
    if errors:
        for error in errors:
            print(f"r7_kat_pin FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "r7_kat_pin check OK "
        f"vectors={count} artifact_sha256={digest} c_bridge=implemented"
    )
    return 0


def run_self_test() -> int:
    errors, count, digest = collect_errors()
    errors.extend(mutation_self_tests() if not errors else [])
    if errors:
        for error in errors:
            print(f"r7_kat_pin self-test FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "r7_kat_pin self-test OK "
        f"vectors={count} artifact_sha256={digest} mutations=13 c_bridge=implemented"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="R7 private KAT fixture gate")
    parser.add_argument("command", choices=("check", "self-test", "emit-sha256"))
    args = parser.parse_args(argv)
    if args.command == "check":
        return run_check()
    if args.command == "self-test":
        return run_self_test()
    if not JSON_FIXTURE.is_file() or not HEADER_FIXTURE.is_file():
        print("fixtures are missing", file=sys.stderr)
        return 1
    print(artifact_digest(JSON_FIXTURE.read_bytes(), HEADER_FIXTURE.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
