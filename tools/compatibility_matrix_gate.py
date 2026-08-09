#!/usr/bin/env python3
"""Fail-closed completion authority for compatibility-matrix.json."""

from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import pathlib
import re
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "compatibility-matrix.json"
STATES = [
    "UNALLOCATED",
    "PROPOSED",
    "SPEC_ACCEPTED",
    "HOST_CANDIDATE",
    "TARGET_CANDIDATE",
    "HIL_VERIFIED",
    "RELEASE_SUPPORTED",
]
TRANSITIONS = {
    "UNALLOCATED": ["PROPOSED"],
    "PROPOSED": ["SPEC_ACCEPTED"],
    "SPEC_ACCEPTED": ["HOST_CANDIDATE", "TARGET_CANDIDATE"],
    "HOST_CANDIDATE": ["TARGET_CANDIDATE", "HIL_VERIFIED", "RELEASE_SUPPORTED"],
    "TARGET_CANDIDATE": ["HIL_VERIFIED"],
    "HIL_VERIFIED": ["RELEASE_SUPPORTED"],
    "RELEASE_SUPPORTED": [],
}
MODULE_API_STATES = [
    "PRIVATE_CANDIDATE",
    "PUBLIC_API_SPEC_ACCEPTED",
    "PACKAGE_EXPERIMENTAL",
    "RELEASE_SUPPORTED",
]
MODULE_API_TRANSITIONS = {
    "PRIVATE_CANDIDATE": ["PUBLIC_API_SPEC_ACCEPTED"],
    "PUBLIC_API_SPEC_ACCEPTED": ["PACKAGE_EXPERIMENTAL"],
    "PACKAGE_EXPERIMENTAL": ["RELEASE_SUPPORTED"],
    "RELEASE_SUPPORTED": [],
}
MATRIX_BOOLEAN_PATH_PATTERNS = (
    r"/platforms/[0-9]+/(?:required_hil|hil_verified)",
    r"/features/[0-9]+/(?:required_hil|hil_verified)",
)
MODULE_API_DOMAIN_AUTHORITY = {
    "manifest_path": "public-module-manifest.json",
    "schema_path": "spec/public-module-manifest-v1.schema.json",
    "schema": "ninlil-public-module-manifest-v1",
    "schema_version": 1,
    "completion_mapping_path": "public-module-manifest.json",
    "completion_mapping_pointer": "/module_api_completion_mapping",
    "identity_attachment_precondition_path": "public-module-manifest.json",
    "identity_attachment_precondition_pointer": (
        "/identity_attachment_precondition_contract"
    ),
    "fabric_selection_port_path": "public-module-manifest.json",
    "fabric_selection_port_pointer": "/fabric_selection_port_contract",
    "acceptance_evidence_contract_path": "public-module-manifest.json",
    "acceptance_evidence_contract_pointer": "/acceptance_evidence_contract",
    "independent_review_contract_path": "public-module-manifest.json",
    "independent_review_contract_pointer": "/independent_review_contract",
    "module_promotion_authority_pointer": "/modules/*/promotion_authority",
    "states": MODULE_API_STATES,
    "allowed_transitions": MODULE_API_TRANSITIONS,
    "supplemental_completion_features": [
        {
            "id": "nfl1-r7-nrw1-rf-mapping",
            "state": "PROPOSED",
            "state_ceiling": "HIL_VERIFIED",
            "depends_on": [
                "fabric-bearer-nfl1-path-registry",
                "nrw1-link-frag-reassembly",
                "identity-attachment-session-install",
            ],
            "authority": "docs/adr/0035-v1-compact-radio-mapping.md",
        }
    ],
}


def ev(evidence_class: str, path: str, contains: str) -> dict[str, str]:
    return {"class": evidence_class, "path": path, "contains": contains}


def validate_boolean_locations(matrix: dict[str, Any]) -> None:
    patterns = tuple(re.compile(value) for value in MATRIX_BOOLEAN_PATH_PATTERNS)

    def walk(value: Any, path: str) -> None:
        if isinstance(value, bool):
            if not any(pattern.fullmatch(path) for pattern in patterns):
                raise GateError(
                    f"matrix{path}: boolean supplied to non-boolean field"
                )
            return
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{path}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}/{index}")

    walk(matrix, "")


# Live 状態 lines anywhere (column-0 or indented); comments stripped first.
# Blockquotes (`> 状態:`) are NOT authoritative status locations.
ADR_STATUS_LINE_RE = re.compile(
    r"^[ \t]*状態:\s*\*\*(?P<body>.+?)\*\*(?P<after>.*)$",
    re.MULTILINE,
)
# Claim-like status smuggling in blockquotes / callouts (not authority, but reject).
BLOCKQUOTE_STATUS_SMUGGLE_RE = re.compile(
    r"^[ \t]*>[ \t]*状態\s*:",
    re.MULTILINE,
)
# HTML comments are not live rendered authority (multiline inclusive).
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# Canonical full Apache-2.0 LICENSE bytes (repository root LICENSE).
# One-line "Apache License" stubs must reject.
APACHE_2_0_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
APACHE_2_0_LICENSE_MIN_BYTES = 10000
# Canonical NOTICE bytes (exact file authority).
NOTICE_SHA256 = (
    "7fe5c13ffc658808747eb361dd14ed17ea912a5e5fe4d8f7a5405bfbb6185319"
)
NOTICE_REQUIRED_AFFIRMATIVE = (
    "This product includes software developed as part of the Ninlil project.",
    "The source code is licensed under the Apache License, Version 2.0.",
    "See LICENSE for the full license text.",
    "Third-party libraries linked by supported builds, target components resolved",
    "from committed manifests, and vendored tooling dependencies shipped in the",
    "source tree are listed in THIRD-PARTY-NOTICES.md.",
)
NOTICE_REQUIRED_TOKENS = (
    "Ninlil",
    "Apache License, Version 2.0",
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
)
# Machine-readable SDK distribution authority (live visible, not HTML-comment-only).
SDK_DISTRIBUTION_MANIFEST_PATH = "docs/sdk-distribution-manifest.md"
SDK_DISTRIBUTION_SCHEMA = "ninlil-sdk-distribution-manifest-v1"

# Completion states as whole tokens (ASCII identifier boundaries).
COMPLETION_STATE_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])("
    + "|".join(re.escape(state) for state in STATES)
    + r")(?![A-Za-z0-9_])"
)

# Independent-review: exactly one verdict; label must not smuggle GO/NO-GO.
# NO-GO is matched before GO so a leading live NO-GO is not absorbed into label.
REVIEW_VERDICT_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])(NO-GO|GO)(?![A-Za-z0-9_-])")
# Structured review counts only (not historical "P0=P1=P2=0" prose).
REVIEW_COUNT_SMUGGLE_RE = re.compile(
    r"P0=(?:0|[1-9]\d*)\s*/\s*P1=(?:0|[1-9]\d*)\s*/\s*P2=(?:0|[1-9]\d*)"
)
INDEPENDENT_REVIEW_STATUS_RE = re.compile(
    r"^(?P<label>(?:(?!\b(?:NO-GO|GO)\b).)+?)\s+"
    r"(?P<verdict>NO-GO|GO)\s*"
    r"[—\-]\s*"
    r"P0=(?P<p0>0|[1-9]\d*)\s*/\s*"
    r"P1=(?P<p1>0|[1-9]\d*)\s*/\s*"
    r"P2=(?P<p2>0|[1-9]\d*)\s*$"
)
REVIEW_COUNTS_TOKEN_RE = re.compile(
    r"^P0=(0|[1-9]\d*)\s*/\s*P1=(0|[1-9]\d*)\s*/\s*P2=(0|[1-9]\d*)$"
)

# In-memory file overlays for self-tests (never write ROOT sources).
_FILE_TEXT_OVERRIDES: dict[str, str] = {}

# README feature ledger row → matrix feature id (exact table row name).
FEATURE_README_ROWS: dict[str, str] = {
    "portable-core-host-runtime": "Portable Core / Host Runtime",
    "canonical-domain-store": "Canonical Domain Store",
    "identity-attachment-session-install": "Identity / Attachment / session install",
    "fabric-bearer-nfl1-path-registry": "Fabric Bearer / NFL1 / path registry",
    "posix-tcp-tls-wifi-reference": "POSIX TCP/TLS Wi-Fi reference",
    "esp32s3-wifi-sta-tcp-tls": "ESP32-S3 Wi-Fi STA/TCP/TLS",
    "nrw1-link-frag-reassembly": "NRW1 LINK / FRAG / reassembly",
    "relay": "Relay",
    "multi-parent-multi-controller": "Multi-parent / multi-Controller",
    "multi-frame-durable-transfer": "Multi-frame durable transfer",
    "v1-functional-lab-vertical-slice": "V1 functional LAB vertical slice",
    "oss-package-docs-release-ci": "OSS package / docs / release CI",
}


PLATFORM_AUTHORITY = {
    "linux-x86_64": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "os": "Linux",
        "runner": "ubuntu-24.04",
        "architecture": "x86_64",
        "workflow": ".github/workflows/ci.yml",
        "toolchain_version": None,
        "evidence": [
            ev("ci-workflow", ".github/workflows/ci.yml", "runs-on: ubuntu-24.04")
        ],
    },
    "macos-arm64": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "os": "macOS",
        "runner": "macos-15",
        "architecture": "arm64",
        "workflow": ".github/workflows/ci.yml",
        "toolchain_version": None,
        "evidence": [
            ev(
                "ci-workflow",
                ".github/workflows/ci.yml",
                'test "$(uname -m)" = "arm64"',
            )
        ],
    },
    "esp32s3-esp-idf": {
        "required_hil": True,
        "state_ceiling": "TARGET_CANDIDATE",
        "os": "ESP-IDF",
        "runner": "ubuntu-24.04",
        "architecture": "xtensa-esp32s3",
        "workflow": ".github/workflows/esp-idf.yml",
        "toolchain_version": "v5.5.3",
        "evidence": [
            ev(
                "target-ci-workflow",
                ".github/workflows/esp-idf.yml",
                "sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb",
            )
        ],
    },
}

VERSION_DOMAIN_AUTHORITY = {
    "public_c_abi": {
        "minimum": 1,
        "maximum": 1,
        "stability": "experimental",
    },
    "foundation_storage_schema": {
        "minimum": 1,
        "maximum": 1,
        "stability": "experimental",
    },
    "public_application_data_wire": {
        "status": "UNALLOCATED",
        "versions": [],
    },
    "ncl1_envelope": {
        "status": "SPEC_ACCEPTED",
        "logical_versions": [1],
    },
    "private_control_protocol": {
        "status": "HOST_CANDIDATE",
        "supported_versions": [1, 2],
        "proposed_versions": [],
    },
    "private_mfdt_protocol": {
        "status": "SPEC_ACCEPTED",
        "versions": [1],
        "bound_base_control_versions": [1, 2],
    },
    "secure_compact_radio_wire": {
        "status": "SPEC_ACCEPTED",
        "wire_profile_ids": [17],
    },
    "canonical_domain_binding": {
        "status": "SPEC_ACCEPTED",
        "read_only_quarantine_formats": [1],
        "reserved_read_write_formats": [2],
    },
}

LEGACY_ADAPTER_AUTHORITY = {"legacy_linkos_lab_wire_1": "unsupported"}

FEATURE_AUTHORITY = {
    "portable-core-host-runtime": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "depends_on": [],
        "evidence": [
            ev("status", "README.md", "SPEC_ACCEPTED"),
            ev("sdk-guide", "docs/host-runtime-sdk.md", "Host Runtime"),
            ev("ci-workflow", ".github/workflows/ci.yml", "name: CI"),
        ],
    },
    "canonical-domain-store": {
        "required_hil": True,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": ["portable-core-host-runtime"],
        "evidence": [
            ev(
                "accepted-adr",
                "docs/adr/0022-domain-store-schema1-runtime-binding.md",
                "SPEC_ACCEPTED",
            ),
            ev(
                "independent-review",
                "docs/reviews/2026-07-29-domain-store-schema1-spec-accepted.md",
                "P0=0 / P1=0 / P2=0",
            ),
        ],
    },
    "identity-attachment-session-install": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": ["portable-core-host-runtime", "canonical-domain-store"],
        "evidence": [
            ev("normative-spec", "docs/03-identity-and-join.md", "Identity"),
            ev("roadmap", "docs/09-roadmap.md", "Roadmap"),
            ev("normative-spec", "docs/30-r6-secure-radio-wire.md", "Secure"),
            ev(
                "normative-spec",
                "docs/adr/0039-identity-attachment-precondition-gate.md",
                "identity_attachment_precondition_contract",
            ),
        ],
    },
    "fabric-bearer-nfl1-path-registry": {
        "required_hil": False,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": [
            "portable-core-host-runtime",
            "canonical-domain-store",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev(
                "accepted-adr",
                "docs/adr/0017-bearer-registry-path-selection.md",
                "SPEC_ACCEPTED",
            ),
            ev(
                "independent-review",
                "docs/reviews/2026-07-29-fabric-bearer-spec-accepted.md",
                "P0=0 / P1=0 / P2=0",
            ),
        ],
    },
    "posix-tcp-tls-wifi-reference": {
        "required_hil": False,
        "state_ceiling": "PROPOSED",
        "depends_on": [
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "evidence": [
            # Canonical exact ADR state token only (qualifiers live on 状態補足).
            ev(
                "proposed-adr",
                "docs/adr/0018-wifi-bearer.md",
                "Proposed",
            )
        ],
    },
    "esp32s3-wifi-sta-tcp-tls": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": [
            "posix-tcp-tls-wifi-reference",
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev(
                "proposed-adr",
                "docs/adr/0018-wifi-bearer.md",
                "Proposed",
            )
        ],
    },
    "nrw1-link-frag-reassembly": {
        "required_hil": True,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": [
            "canonical-domain-store",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev("normative-spec", "docs/30-r6-secure-radio-wire.md", "Secure"),
            ev(
                "accepted-adr",
                "docs/adr/0010-r6-secure-radio-wire.md",
                "Accepted",
            ),
        ],
    },
    "relay": {
        "required_hil": True,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": [
            "fabric-bearer-nfl1-path-registry",
            "nrw1-link-frag-reassembly",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev(
                "accepted-adr",
                "docs/adr/0019-route-relay.md",
                "Accepted / SPEC_ACCEPTED",
            ),
            ev(
                "work-record",
                "docs/work/2026-07-30-rrmp-spec-accepted-promotion.md",
                "P0=0 / P1=0",
            ),
        ],
    },
    "multi-parent-multi-controller": {
        "required_hil": True,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": ["relay", "identity-attachment-session-install"],
        "evidence": [
            ev(
                "accepted-adr",
                "docs/adr/0020-multi-parent.md",
                "Accepted / SPEC_ACCEPTED",
            ),
            ev(
                "work-record",
                "docs/work/2026-07-30-rrmp-spec-accepted-promotion.md",
                "P0=0 / P1=0",
            ),
        ],
    },
    "multi-frame-durable-transfer": {
        "required_hil": True,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": [
            "portable-core-host-runtime",
            "canonical-domain-store",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev(
                "accepted-adr",
                "docs/adr/0021-multi-frame-durable-custody.md",
                "Accepted baseline / Application-handoff amendment SPEC_ACCEPTED",
            ),
            ev(
                "work-record",
                "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md",
                "P0=0 / P1=0 / P2=0",
            ),
        ],
    },
    "v1-functional-lab-vertical-slice": {
        "required_hil": True,
        "state_ceiling": "HIL_VERIFIED",
        "depends_on": [
            "portable-core-host-runtime",
            "fabric-bearer-nfl1-path-registry",
        ],
        "evidence": [
            ev(
                "accepted-adr",
                "docs/adr/0034-v1-functional-lab-scope.md",
                "ACCEPTED",
            ),
            ev(
                "independent-review",
                "docs/reviews/2026-08-03-v1-functional-lab-scope-review.md",
                "P0=0 / P1=0 / P2=0",
            ),
        ],
    },
    "oss-package-docs-release-ci": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "depends_on": [],
        "evidence": [
            ev("license", "LICENSE", "Apache License"),
            ev("notice", "NOTICE", "Ninlil"),
            ev(
                "dependency-inventory",
                "dependency-inventory.json",
                "ninlil-dependency-inventory-v1",
            ),
            ev(
                "work-record",
                "docs/work/2026-07-28-oss-compatibility-authority.md",
                "compatibility",
            ),
            ev("release-guide", "docs/releasing.md", "Release Guide"),
            ev(
                "release-workflow",
                ".github/workflows/release.yml",
                "name: Release",
            ),
        ],
    },
}


class GateError(RuntimeError):
    """A deterministic compatibility authority failure."""


def _rel_key(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def read_text(path: pathlib.Path) -> str:
    key = _rel_key(path)
    if key in _FILE_TEXT_OVERRIDES:
        return _FILE_TEXT_OVERRIDES[key]
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc


def snapshot_source_metadata(paths: list[pathlib.Path]) -> dict[str, tuple]:
    """Capture inode/size/mode/mtime_ns/ctime_ns/sha256 for invariance checks."""
    out: dict[str, tuple] = {}
    for path in paths:
        st = path.stat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        out[str(path.resolve())] = (
            getattr(st, "st_ino", None),
            st.st_size,
            st.st_mode,
            getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)),
            getattr(st, "st_ctime_ns", int(st.st_ctime * 1_000_000_000)),
            digest,
        )
    return out


def assert_source_metadata_unchanged(
    before: dict[str, tuple],
    paths: list[pathlib.Path],
    label: str,
) -> None:
    after = snapshot_source_metadata(paths)
    if after != before:
        raise GateError(f"self-test mutated source metadata ({label}): drift detected")


def load_matrix() -> dict[str, Any]:
    try:
        value = json.loads(read_text(MATRIX_PATH))
    except json.JSONDecodeError as exc:
        raise GateError(f"compatibility-matrix.json is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError("compatibility matrix must be an object")
    return value


def exact_regex(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise GateError(f"{label}: expected exactly one match, got {len(matches)}")
    value = matches[0]
    if isinstance(value, tuple):
        raise GateError(f"{label}: internal regex must have one capture")
    return value


def strip_html_comments(text: str) -> str:
    """Remove HTML comments so only live/rendered markdown is authority."""
    return HTML_COMMENT_RE.sub("", text)


FENCED_CODE_RE = re.compile(r"```.*?```", re.DOTALL)


def strip_fenced_code(text: str) -> str:
    """Remove fenced code blocks; status authority cannot live inside fences."""
    return FENCED_CODE_RE.sub("", text)


def live_markdown_text(text: str) -> str:
    """Live markdown for general authority: HTML comments are not authority."""
    return strip_html_comments(text)


def live_status_markdown_text(text: str) -> str:
    """Live text for 状態: authority — comments and fenced code are non-authority."""
    return strip_fenced_code(strip_html_comments(text))


def live_status_matches(live: str) -> list[re.Match[str]]:
    """All live 状態 lines, including indented column > 0."""
    return list(ADR_STATUS_LINE_RE.finditer(live))


def reject_blockquote_status_smuggling(live: str, label: str) -> None:
    """Blockquotes are not status authority; claim-like 状態 there is rejected."""
    for match in BLOCKQUOTE_STATUS_SMUGGLE_RE.finditer(live):
        # Take the blockquote line body for claim detection.
        line_end = live.find("\n", match.start())
        line = live[match.start() : line_end if line_end != -1 else len(live)]
        states = completion_state_tokens(line)
        verdicts = REVIEW_VERDICT_TOKEN_RE.findall(line)
        if states or verdicts or "RELEASE_SUPPORTED" in line or "HIL_VERIFIED" in line:
            raise GateError(
                f"{label}: blockquote status smuggling is not authoritative "
                f"and is rejected (line={line!r})"
            )
        # Even without a completion token, a blockquote `状態:` claim is rejected
        # so authority cannot move into callouts.
        raise GateError(
            f"{label}: blockquote 状態: is not an authoritative status location "
            f"(line={line!r})"
        )


def exact_adr_status_body(text: str, label: str) -> str:
    """Return the unique live ADR/review 状態 bold body; reject line conflicts.

    Contract:
    - Strip HTML comments, then require exactly one live `状態:` line in
      authoritative locations (column-0 or indented; **not** blockquotes).
    - Blockquote `> 状態:` claim-like lines are rejected as smuggling.
    - Authoritative state is the first bold token body on that line.
    - Text after the closing `**` on the same line must not carry completion
      states, GO/NO-GO verdicts, or P0/P1/P2 counts (rejects
      `**SPEC_ACCEPTED** — RELEASE_SUPPORTED` and GO-bold + trailing NO-GO).
    """
    live = live_status_markdown_text(text)
    reject_blockquote_status_smuggling(live, label)
    matches = live_status_matches(live)
    if len(matches) != 1:
        raise GateError(
            f"{label}: expected exactly one live 状態 status line "
            f"(including indented), got {len(matches)}"
        )
    match = matches[0]
    body = match.group("body")
    after = match.group("after") or ""
    after_states = completion_state_tokens(after)
    if after_states:
        raise GateError(
            f"{label}: live status line has contradictory completion token(s) "
            f"after closing bold: {after_states!r} (after={after!r})"
        )
    after_verdicts = REVIEW_VERDICT_TOKEN_RE.findall(after)
    if after_verdicts:
        raise GateError(
            f"{label}: live status line has contradictory verdict after closing "
            f"bold: {after_verdicts!r} (after={after!r})"
        )
    if REVIEW_COUNT_SMUGGLE_RE.search(after):
        raise GateError(
            f"{label}: live status line has contradictory P0/P1/P2 counts after "
            f"closing bold (after={after!r})"
        )
    return body


def completion_state_tokens(text: str) -> list[str]:
    """Return completion-state tokens found as whole words in text."""
    return COMPLETION_STATE_TOKEN_RE.findall(text)


def status_body_binds_token(body: str, token: str) -> bool:
    """True when bold body carries canonical exact state authority.

    - Full multi-word phrases must equal the whole body exactly.
    - Single completion-state tokens must be the sole STATES token in the body.
    - Single ADR words (Proposed / Accepted) must lead with no STATES in body.
    - ASCII identifier extension is rejected.
    """
    body_states = completion_state_tokens(body)
    token_states = completion_state_tokens(token)

    if body == token:
        return True

    if not body.startswith(token):
        return False
    rest = body[len(token) :]
    if rest:
        first = rest[0]
        if first.isascii() and (first.isalnum() or first == "_"):
            return False

    if token in STATES:
        return body_states == [token]

    if body_states:
        return False
    if token_states:
        return False
    return True


def parse_independent_review_status(body: str, label: str) -> dict[str, Any]:
    """Parse independent-review bold body into structured verdict + counts."""
    verdicts = REVIEW_VERDICT_TOKEN_RE.findall(body)
    if len(verdicts) != 1:
        raise GateError(
            f"{label}: independent-review status must contain exactly one live "
            f"GO|NO-GO verdict, got {verdicts!r} (body={body!r})"
        )
    match = INDEPENDENT_REVIEW_STATUS_RE.fullmatch(body)
    if match is None:
        raise GateError(
            f"{label}: independent-review status body is not structured "
            f"label + GO|NO-GO + P0/P1/P2 authority (body={body!r})"
        )
    if match.group("verdict") != verdicts[0]:
        raise GateError(
            f"{label}: independent-review verdict parse ambiguity "
            f"(parsed={match.group('verdict')!r} tokens={verdicts!r})"
        )
    return {
        "label": match.group("label"),
        "verdict": match.group("verdict"),
        "p0": int(match.group("p0")),
        "p1": int(match.group("p1")),
        "p2": int(match.group("p2")),
    }


def parse_review_counts_token(token: str, label: str) -> tuple[int, int, int]:
    """Parse evidence contains token as exact P0/P1/P2 counts authority."""
    match = REVIEW_COUNTS_TOKEN_RE.fullmatch(token)
    if match is None:
        raise GateError(
            f"{label}: independent-review evidence token must be exact "
            f"P0=N / P1=N / P2=N (token={token!r})"
        )
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def exact_readme_feature_cell(text: str, row_name: str, label: str) -> str:
    """Return the unique README ledger current-state cell for a feature row."""
    pattern = re.compile(
        rf"^\| {re.escape(row_name)} \| \*\*(?P<cell>.+?)\*\* \|",
        re.MULTILINE,
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise GateError(
            f"{label}: expected exactly one README status row for {row_name!r}, "
            f"got {len(matches)}"
        )
    return matches[0]


def read_bytes_for_path(path: pathlib.Path) -> bytes:
    """Read bytes, honoring in-memory text overlays used by self-tests."""
    key = _rel_key(path)
    if key in _FILE_TEXT_OVERRIDES:
        return _FILE_TEXT_OVERRIDES[key].encode("utf-8")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise GateError(f"cannot read bytes {path}: {exc}") from exc


def verify_apache_license_bytes(path: pathlib.Path, label: str) -> None:
    """Require canonical full Apache-2.0 LICENSE bytes (pinned SHA-256)."""
    payload = read_bytes_for_path(path)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != APACHE_2_0_LICENSE_SHA256:
        raise GateError(
            f"{label}: LICENSE sha256 mismatch: got {digest}, "
            f"expected {APACHE_2_0_LICENSE_SHA256}"
        )
    if len(payload) < APACHE_2_0_LICENSE_MIN_BYTES:
        raise GateError(
            f"{label}: LICENSE is too short to be full Apache-2.0 text "
            f"({len(payload)} bytes)"
        )
    text = payload.decode("utf-8")
    for needle in (
        "Apache License",
        "Version 2.0, January 2004",
        "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
        "END OF TERMS AND CONDITIONS",
        "APPENDIX: How to apply the Apache License to your work.",
    ):
        if needle not in text:
            raise GateError(f"{label}: LICENSE missing required clause: {needle!r}")
    # One-line stubs / truncated Apache notices must reject.
    if text.count("\n") < 100:
        raise GateError(f"{label}: LICENSE must be the full multi-section Apache-2.0 text")


def verify_notice_obligations(path: pathlib.Path, label: str) -> None:
    """Require canonical NOTICE bytes + affirmative obligation clauses.

    Negated sentences that still contain obligation substrings must reject.
    """
    payload = read_bytes_for_path(path)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != NOTICE_SHA256:
        raise GateError(
            f"{label}: NOTICE sha256 mismatch: got {digest}, expected {NOTICE_SHA256}"
        )
    text = payload.decode("utf-8")
    if not text.lstrip().startswith("Ninlil"):
        raise GateError(f"{label}: NOTICE must start with project identity Ninlil")
    for clause in NOTICE_REQUIRED_AFFIRMATIVE:
        if clause not in text:
            raise GateError(
                f"{label}: NOTICE missing required affirmative clause {clause!r}"
            )
    # Reject common negation smuggling around affirmative tokens.
    lowered = text.lower()
    for bad in (
        "does not include",
        "not licensed under the apache",
        "not under the apache",
        "see license nowhere",
        "not third-party-notices",
    ):
        if bad in lowered:
            raise GateError(
                f"{label}: NOTICE contains negation smuggling {bad!r}"
            )


def live_structured_json_blocks(text: str) -> list[dict[str, Any]]:
    """Extract JSON objects from live (non-HTML-comment) fenced ```json blocks."""
    live = live_markdown_text(text)
    blocks: list[dict[str, Any]] = []
    pattern = re.compile(r"```json\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
    for match in pattern.finditer(live):
        body = match.group(1).strip()
        try:
            value = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            blocks.append(value)
    return blocks


def verify_sdk_distribution_manifest(path: pathlib.Path, label: str, token: str) -> None:
    """Require machine-readable live structured authority (not HTML-comment-only)."""
    raw = read_text(path)
    live = live_markdown_text(raw)
    if token not in live:
        # Schema only inside HTML comments is not authority.
        if token in raw:
            raise GateError(
                f"{label}: distribution manifest schema {token!r} exists only in "
                f"HTML comments; live structured authority is required"
            )
        raise GateError(
            f"{label}: distribution manifest missing live schema token {token!r}"
        )
    blocks = live_structured_json_blocks(raw)
    matches = [b for b in blocks if b.get("schema") == token]
    if len(matches) != 1:
        raise GateError(
            f"{label}: expected exactly one live ```json authority block with "
            f"schema {token!r}, got {len(matches)}"
        )
    manifest = matches[0]
    required = {
        "schema",
        "runtime_release_source",
        "license",
        "notice",
        "compatibility_matrix",
        "dependency_inventory",
        "release_workflow",
        "sbom_tool",
    }
    if set(manifest) != required:
        raise GateError(
            f"{label}: sdk distribution manifest fields are not closed: "
            f"{sorted(manifest)}"
        )
    if manifest.get("license") != {
        "path": "LICENSE",
        "spdx": "Apache-2.0",
        "sha256": APACHE_2_0_LICENSE_SHA256,
    }:
        raise GateError(f"{label}: sdk distribution manifest license authority drift")
    if manifest.get("notice") != {
        "path": "NOTICE",
        "obligations": list(NOTICE_REQUIRED_TOKENS),
    }:
        raise GateError(f"{label}: sdk distribution manifest notice authority drift")
    if manifest.get("compatibility_matrix") != "compatibility-matrix.json":
        raise GateError(f"{label}: sdk distribution matrix path drift")
    if manifest.get("dependency_inventory") != "dependency-inventory.json":
        raise GateError(f"{label}: sdk distribution inventory path drift")
    if manifest.get("release_workflow") != ".github/workflows/release.yml":
        raise GateError(f"{label}: sdk distribution release workflow drift")
    if manifest.get("sbom_tool") != {
        "action": (
            "anchore/sbom-action/download-syft@"
            "e22c389904149dbc22b58101806040fa8d37a610"
        ),
        "syft_version": "v1.49.0",
    }:
        raise GateError(f"{label}: sdk distribution SBOM tool identity drift")
    if manifest.get("runtime_release_source") != "CMakeLists.txt project(VERSION)":
        raise GateError(f"{label}: sdk distribution runtime_release_source drift")


def check_evidence_content(
    item: dict[str, str],
    label: str,
) -> None:
    path_text = item["path"]
    path = ROOT / path_text
    if not path.is_file():
        raise GateError(f"{label}: evidence file absent: {path_text}")
    text = read_text(path)
    token = item["contains"]
    evidence_class = item["class"]

    if evidence_class in ("proposed-adr", "accepted-adr"):
        body = exact_adr_status_body(text, label)
        if not status_body_binds_token(body, token):
            raise GateError(
                f"{label}: ADR status line does not bind required state token "
                f"{token!r} (body={body!r}) in {path_text}"
            )
        return

    if evidence_class == "independent-review":
        body = exact_adr_status_body(text, label)
        parsed = parse_independent_review_status(body, label)
        expected_p0, expected_p1, expected_p2 = parse_review_counts_token(token, label)
        if parsed["verdict"] != "GO":
            raise GateError(
                f"{label}: independent-review verdict must be exact GO "
                f"(got {parsed['verdict']!r}) in {path_text}"
            )
        actual = (parsed["p0"], parsed["p1"], parsed["p2"])
        expected = (expected_p0, expected_p1, expected_p2)
        if actual != expected:
            raise GateError(
                f"{label}: independent-review P0/P1/P2 counts mismatch "
                f"(status={actual!r} required={expected!r}) in {path_text}"
            )
        # Forbid smuggled extra completion-state tokens on the review status body
        # beyond those already present in the structured label (e.g. SPEC_ACCEPTED).
        if "RELEASE_SUPPORTED" in completion_state_tokens(body):
            raise GateError(
                f"{label}: independent-review status must not smuggle "
                f"RELEASE_SUPPORTED in {path_text}"
            )
        # Domain-store review also carries the versioned four-file manifest.
        if path_text.endswith(
            "2026-07-29-domain-store-schema1-spec-accepted.md"
        ):
            try:
                from domain_store_schema1_review_manifest_gate import (  # type: ignore
                    check as check_review_manifest,
                )
            except ImportError:
                # Same-directory import when executed as a script.
                import importlib.util

                manifest_path = ROOT / "tools" / "domain_store_schema1_review_manifest_gate.py"
                spec = importlib.util.spec_from_file_location(
                    "domain_store_schema1_review_manifest_gate",
                    manifest_path,
                )
                assert spec and spec.loader
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                check_review_manifest = mod.check
            try:
                check_review_manifest(ROOT)
            except Exception as exc:  # GateError from manifest tool
                raise GateError(
                    f"{label}: domain review manifest authority failed: {exc}"
                ) from exc
        return

    if evidence_class == "status":
        # Feature completion status on the README ledger row (not whole-file).
        if path_text != "README.md":
            raise GateError(f"{label}: status evidence must target README.md")
        # portable-core is the only feature using class=status today; bind its row.
        row_name = FEATURE_README_ROWS["portable-core-host-runtime"]
        cell = exact_readme_feature_cell(text, row_name, label)
        if not status_body_binds_token(cell, token):
            raise GateError(
                f"{label}: README status cell does not bind required state token "
                f"{token!r} (cell={cell!r}) for {row_name!r}"
            )
        return

    if evidence_class == "license":
        if path_text != "LICENSE":
            raise GateError(f"{label}: license evidence must target LICENSE")
        # Token remains the closed matrix authority string; full-bytes pin is required.
        if token not in text:
            raise GateError(
                f"{label}: required content absent from {path_text}: {token!r}"
            )
        verify_apache_license_bytes(path, label)
        return

    if evidence_class == "notice":
        if path_text != "NOTICE":
            raise GateError(f"{label}: notice evidence must target NOTICE")
        if token not in text:
            raise GateError(
                f"{label}: required content absent from {path_text}: {token!r}"
            )
        verify_notice_obligations(path, label)
        return

    # Non-status evidence: exact closed authority substring (not free-form scan).
    if token not in text:
        raise GateError(
            f"{label}: required content absent from {path_text}: {token!r}"
        )


def check_evidence(
    value: Any,
    expected: list[dict[str, str]],
    label: str,
) -> None:
    if value != expected:
        raise GateError(f"{label}: evidence class/path/content authority drift")
    for index, item in enumerate(expected):
        check_evidence_content(item, f"{label}[{index}]")


def check_feature_readme_state(feature_id: str, state: str, label: str) -> None:
    """Bind matrix feature state to the exact README ledger current-state cell."""
    row_name = FEATURE_README_ROWS.get(feature_id)
    if row_name is None:
        raise GateError(f"{label}: missing README row authority mapping")
    readme = read_text(ROOT / "README.md")
    cell = exact_readme_feature_cell(readme, row_name, label)
    if not status_body_binds_token(cell, state):
        raise GateError(
            f"{label}: README current-state cell does not bind matrix state "
            f"{state!r} (cell={cell!r}) for {row_name!r}"
        )


def check_attestation(
    value: Any,
    label: str,
    expected_class: str,
    allowed_platforms: set[str],
    expected_subject: str,
) -> None:
    minimum = 2 if expected_class == "hil-result" else 3
    if not isinstance(value, list) or len(value) < minimum:
        raise GateError(
            f"{label}: at least {minimum} attestation references are required"
        )
    identities: set[tuple[str, str]] = set()
    for index, reference in enumerate(value):
        if not isinstance(reference, dict) or set(reference) != {
            "class",
            "path",
            "sha256",
        }:
            raise GateError(f"{label}[{index}]: reference fields are not closed")
        if reference["class"] != expected_class:
            raise GateError(f"{label}[{index}]: evidence class mismatch")
        path_text = reference["path"]
        prefix = f"evidence/{'hil' if expected_class == 'hil-result' else 'release'}/"
        if not isinstance(path_text, str) or not path_text.startswith(prefix):
            raise GateError(f"{label}[{index}]: evidence path outside {prefix}")
        digest = reference["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GateError(f"{label}[{index}]: invalid sha256")
        path = ROOT / path_text
        payload = path.read_bytes() if path.is_file() else None
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            raise GateError(f"{label}[{index}]: absent or digest-mismatched artifact")
        identity = (path_text, digest)
        if identity in identities:
            raise GateError(f"{label}[{index}]: duplicate evidence reference")
        identities.add(identity)
        try:
            record = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise GateError(f"{label}[{index}]: invalid JSON artifact: {exc}") from exc
        check_verification_record(
            record,
            f"{label}[{index}]",
            allowed_platforms,
            expected_subject,
        )


def check_verification_record(
    record: Any,
    label: str,
    allowed_platforms: set[str],
    expected_subject: str,
) -> None:
    expected_fields = {
        "schema",
        "commit",
        "subject_id",
        "test_id",
        "platform_id",
        "result",
        "timestamp",
    }
    if not isinstance(record, dict) or set(record) != expected_fields:
        raise GateError(f"{label}: artifact fields are not closed")
    if record["schema"] != "ninlil-verification-evidence-v1":
        raise GateError(f"{label}: artifact schema mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", str(record["commit"])):
        raise GateError(f"{label}: commit must be a full SHA")
    if record["subject_id"] != expected_subject:
        raise GateError(f"{label}: subject_id mismatch")
    if not isinstance(record["test_id"], str) or not record["test_id"]:
        raise GateError(f"{label}: test_id is required")
    if record["platform_id"] not in allowed_platforms:
        raise GateError(f"{label}: platform_id mismatch")
    if record["result"] != "PASS":
        raise GateError(f"{label}: result must be PASS")
    timestamp = str(record["timestamp"])
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        timestamp,
    ):
        raise GateError(f"{label}: timestamp must be UTC RFC3339")
    try:
        datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GateError(f"{label}: timestamp is not a real UTC date/time") from exc


def check_versions(matrix: dict[str, Any]) -> None:
    cmake = read_text(ROOT / "CMakeLists.txt")
    version = exact_regex(
        cmake,
        r"^project\(ninlil VERSION ([0-9]+\.[0-9]+\.[0-9]+) LANGUAGES C CXX\)$",
        "CMake project version",
    )
    if matrix.get("runtime_release") != version:
        raise GateError("runtime_release/CMake version drift")
    inventory = json.loads(read_text(ROOT / "dependency-inventory.json"))
    if inventory["project"]["version"] != version:
        raise GateError("dependency inventory project version drift")
    component = read_text(ROOT / "ports/esp-idf/components/ninlil/idf_component.yml")
    if exact_regex(
        component,
        r'^version: "([0-9]+\.[0-9]+\.[0-9]+)"$',
        "ESP component version",
    ) != version:
        raise GateError("ESP component/CMake version drift")
    header = read_text(ROOT / "include/ninlil/version.h")
    abi = int(
        exact_regex(
            header,
            r"^#define NINLIL_ABI_VERSION\s+\(\(uint16_t\)0x([0-9A-Fa-f]{4})u\)$",
            "public ABI version",
        ),
        16,
    )
    storage = int(
        exact_regex(
            header,
            r"^#define NINLIL_STORAGE_SCHEMA_M1A\s+\(\(uint32_t\)([0-9]+)u\)$",
            "storage schema",
        )
    )
    domains = matrix.get("version_domains")
    expected_domains = copy.deepcopy(VERSION_DOMAIN_AUTHORITY)
    expected_domains["public_c_abi"]["minimum"] = abi
    expected_domains["public_c_abi"]["maximum"] = abi
    expected_domains["foundation_storage_schema"]["minimum"] = storage
    expected_domains["foundation_storage_schema"]["maximum"] = storage
    if domains != expected_domains:
        raise GateError("version domain authority drift")
    if domains["public_c_abi"]["minimum"] != abi:
        raise GateError("public ABI minimum drift")
    if domains.get("public_c_abi", {}).get("maximum") != abi:
        raise GateError("public ABI maximum drift")
    if domains.get("foundation_storage_schema", {}).get("minimum") != storage:
        raise GateError("storage schema minimum drift")
    if domains.get("foundation_storage_schema", {}).get("maximum") != storage:
        raise GateError("storage schema maximum drift")


def check_platforms(matrix: dict[str, Any]) -> None:
    platforms = matrix.get("platforms")
    if not isinstance(platforms, list):
        raise GateError("platforms must be an array")
    ids = [item.get("id") if isinstance(item, dict) else None for item in platforms]
    if ids != list(PLATFORM_AUTHORITY):
        raise GateError("platform ID/order authority drift")
    for item in platforms:
        platform_id = item["id"]
        authority = PLATFORM_AUTHORITY[platform_id]
        allowed_fields = {
            "id",
            "os",
            "architecture",
            "state",
            "state_ceiling",
            "toolchain_version",
            "ci_workflow",
            "ci_runner",
            "required_hil",
            "hil_verified",
            "evidence",
            "hil_evidence",
            "release_evidence",
        }
        if set(item) - allowed_fields:
            raise GateError(f"{platform_id}: unknown platform fields")
        if item.get("required_hil") is not authority["required_hil"]:
            raise GateError(f"{platform_id}: required_hil authority drift")
        if item.get("state_ceiling") != authority["state_ceiling"]:
            raise GateError(f"{platform_id}: state ceiling authority drift")
        if item.get("architecture") != authority["architecture"]:
            raise GateError(f"{platform_id}: architecture authority drift")
        if item.get("os") != authority["os"]:
            raise GateError(f"{platform_id}: OS authority drift")
        if item.get("ci_workflow") != authority["workflow"]:
            raise GateError(f"{platform_id}: CI workflow authority drift")
        if item.get("toolchain_version") != authority["toolchain_version"]:
            raise GateError(f"{platform_id}: toolchain version authority drift")
        if item.get("ci_runner") != authority["runner"]:
            raise GateError(f"{platform_id}: CI runner authority drift")
        state = item.get("state")
        if state not in STATES or STATES.index(state) > STATES.index(
            authority["state_ceiling"]
        ):
            raise GateError(f"{platform_id}: state exceeds accepted ceiling")
        check_evidence(item.get("evidence"), authority["evidence"], platform_id)
        if authority["runner"] not in read_text(ROOT / item["ci_workflow"]):
            raise GateError(f"{platform_id}: runner absent from workflow")
        if authority["required_hil"]:
            reached_hil = STATES.index(state) >= STATES.index("HIL_VERIFIED")
            if item.get("hil_verified") is not reached_hil:
                raise GateError(f"{platform_id}: hil_verified/state mismatch")
            if not reached_hil and "hil_evidence" in item:
                raise GateError(f"{platform_id}: HIL evidence forbidden while false")
        elif "hil_verified" in item or "hil_evidence" in item:
            raise GateError(f"{platform_id}: HIL fields forbidden by authority")
        if state != "RELEASE_SUPPORTED" and "release_evidence" in item:
            raise GateError(f"{platform_id}: release evidence forbidden before release")
        if authority["required_hil"] and STATES.index(state) >= STATES.index(
            "HIL_VERIFIED"
        ):
            check_attestation(
                item.get("hil_evidence"),
                f"{platform_id}.hil_evidence",
                "hil-result",
                {platform_id},
                platform_id,
            )
        if state == "RELEASE_SUPPORTED":
            check_attestation(
                item.get("release_evidence"),
                f"{platform_id}.release_evidence",
                "release-result",
                {platform_id},
                platform_id,
            )


def check_features(matrix: dict[str, Any]) -> None:
    features = matrix.get("features")
    if not isinstance(features, list):
        raise GateError("features must be an array")
    ids = [item.get("id") if isinstance(item, dict) else None for item in features]
    if ids != list(FEATURE_AUTHORITY):
        raise GateError("feature ID/order authority drift")
    by_id = {item["id"]: item for item in features}
    for item in features:
        feature_id = item["id"]
        authority = FEATURE_AUTHORITY[feature_id]
        allowed_fields = {
            "id",
            "state",
            "state_ceiling",
            "required_hil",
            "hil_verified",
            "depends_on",
            "evidence",
            "hil_evidence",
            "release_evidence",
        }
        if set(item) - allowed_fields:
            raise GateError(f"{feature_id}: unknown feature fields")
        if item.get("required_hil") is not authority["required_hil"]:
            raise GateError(f"{feature_id}: required_hil authority drift")
        if item.get("state_ceiling") != authority["state_ceiling"]:
            raise GateError(f"{feature_id}: state ceiling authority drift")
        if item.get("depends_on") != authority["depends_on"]:
            raise GateError(f"{feature_id}: dependency authority drift")
        state = item.get("state")
        if state not in STATES or STATES.index(state) > STATES.index(
            authority["state_ceiling"]
        ):
            raise GateError(f"{feature_id}: state exceeds accepted ceiling")
        check_evidence(item.get("evidence"), authority["evidence"], feature_id)
        check_feature_readme_state(feature_id, state, f"{feature_id}.readme")
        if authority["required_hil"]:
            reached_hil = STATES.index(state) >= STATES.index("HIL_VERIFIED")
            if item.get("hil_verified") is not reached_hil:
                raise GateError(f"{feature_id}: hil_verified/state mismatch")
            if not reached_hil and "hil_evidence" in item:
                raise GateError(f"{feature_id}: HIL evidence forbidden while false")
        elif "hil_verified" in item or "hil_evidence" in item:
            raise GateError(f"{feature_id}: HIL fields forbidden by authority")
        if state != "RELEASE_SUPPORTED" and "release_evidence" in item:
            raise GateError(f"{feature_id}: release evidence forbidden before release")
        if authority["required_hil"] and STATES.index(state) >= STATES.index(
            "HIL_VERIFIED"
        ):
            check_attestation(
                item.get("hil_evidence"),
                f"{feature_id}.hil_evidence",
                "hil-result",
                set(PLATFORM_AUTHORITY),
                feature_id,
            )
        if state == "RELEASE_SUPPORTED":
            for dependency in authority["depends_on"]:
                if by_id[dependency]["state"] != "RELEASE_SUPPORTED":
                    raise GateError(
                        f"{feature_id}: dependency {dependency} is not release-supported"
                    )
            check_attestation(
                item.get("release_evidence"),
                f"{feature_id}.release_evidence",
                "release-result",
                set(PLATFORM_AUTHORITY),
                feature_id,
            )


def check(matrix: dict[str, Any]) -> None:
    validate_boolean_locations(matrix)
    expected_top = {
        "schema",
        "runtime_release",
        "completion_states",
        "allowed_transitions",
        "module_api_domain",
        "version_domains",
        "platforms",
        "features",
        "legacy_adapters",
        "hardware_regulatory_claim",
    }
    if set(matrix) != expected_top:
        raise GateError("top-level fields are not closed")
    if matrix.get("schema") != "ninlil-compatibility-matrix-v1":
        raise GateError("schema mismatch")
    if matrix.get("completion_states") != STATES:
        raise GateError("completion state order drift")
    if matrix.get("allowed_transitions") != TRANSITIONS:
        raise GateError("allowed transition graph drift")
    if matrix.get("module_api_domain") != MODULE_API_DOMAIN_AUTHORITY:
        raise GateError("module API domain authority drift")
    if matrix.get("hardware_regulatory_claim") != "LAB_ONLY":
        raise GateError("hardware regulatory claim exceeds accepted scope")
    if matrix.get("legacy_adapters") != LEGACY_ADAPTER_AUTHORITY:
        raise GateError("legacy adapter authority drift")
    check_versions(matrix)
    check_platforms(matrix)
    check_features(matrix)
    # Distribution manifest authority is live structured JSON, not HTML comments.
    verify_sdk_distribution_manifest(
        ROOT / SDK_DISTRIBUTION_MANIFEST_PATH,
        "sdk-distribution-manifest",
        SDK_DISTRIBUTION_SCHEMA,
    )
    cmake = read_text(ROOT / "CMakeLists.txt")
    for install_rule in (
        "install(FILES compatibility-matrix.json\n"
        "    DESTINATION ${CMAKE_INSTALL_DATADIR}/ninlil)",
        "install(FILES dependency-inventory.json\n"
        "    DESTINATION ${CMAKE_INSTALL_DATADIR}/ninlil)",
    ):
        if cmake.count(install_rule) != 1:
            raise GateError(f"missing exact install rule: {install_rule}")


def self_test() -> None:
    # Self-tests never write ROOT sources — only in-memory overlays + matrix copies.
    watched = [
        ROOT / "README.md",
        ROOT / "docs/adr/0017-bearer-registry-path-selection.md",
        ROOT / "docs/adr/0018-wifi-bearer.md",
        ROOT / "docs/adr/0022-domain-store-schema1-runtime-binding.md",
        ROOT
        / "docs/reviews/2026-07-29-domain-store-schema1-spec-accepted.md",
        ROOT / ".github/workflows/esp-idf.yml",
        ROOT / "compatibility-matrix.json",
        ROOT / "LICENSE",
        ROOT / "NOTICE",
        ROOT / SDK_DISTRIBUTION_MANIFEST_PATH,
    ]
    meta_before = snapshot_source_metadata(watched)
    if _FILE_TEXT_OVERRIDES:
        raise GateError("self-test started with non-empty file overlays")

    baseline = load_matrix()
    check(baseline)
    valid_record = {
        "schema": "ninlil-verification-evidence-v1",
        "commit": "a" * 40,
        "subject_id": "esp32s3-esp-idf",
        "test_id": "esp32s3-real-ap-e2e",
        "platform_id": "esp32s3-esp-idf",
        "result": "PASS",
        "timestamp": "2026-07-29T00:00:00Z",
    }
    check_verification_record(
        valid_record,
        "positive evidence record",
        {"esp32s3-esp-idf"},
        "esp32s3-esp-idf",
    )

    def reject(label: str, mutation: dict[str, Any]) -> None:
        try:
            check(mutation)
        except GateError:
            return
        raise GateError(f"self-test mutation was accepted: {label}")

    def reject_file_mutation(
        label: str,
        path: pathlib.Path,
        mutate,
    ) -> None:
        """Mutate via in-memory overlay only — never write ROOT paths."""
        rel = _rel_key(path)
        original = read_text(path)
        meta = snapshot_source_metadata([path])
        try:
            mutated = mutate(original)
            if mutated == original:
                raise GateError(f"self-test mutation produced no change: {label}")
            _FILE_TEXT_OVERRIDES[rel] = mutated
            try:
                check(load_matrix())
            except GateError:
                return
            raise GateError(f"self-test mutation was accepted: {label}")
        finally:
            _FILE_TEXT_OVERRIDES.pop(rel, None)
            assert_source_metadata_unchanged(meta, [path], label)

    def rewrite_adr_status(text: str, new_body: str) -> str:
        # Rewrite the first live 状態 bold body (keep indent; drop after-bold tail).
        live_matches = live_status_matches(live_status_markdown_text(text))
        if len(live_matches) != 1:
            raise GateError(
                f"self-test could not locate unique live ADR status line "
                f"(found {len(live_matches)})"
            )

        def _sub(m: re.Match[str]) -> str:
            line_prefix = text[m.start() : m.start("body")]
            return f"{line_prefix}{new_body}**"

        replaced, count = ADR_STATUS_LINE_RE.subn(_sub, text, count=1)
        if count != 1:
            raise GateError("self-test could not rewrite ADR status line")
        return replaced

    def append_after_bold(text: str, suffix: str) -> str:
        """Append live contradictory text after the closing ** on the status line."""

        def _sub(m: re.Match[str]) -> str:
            return f"{m.group(0).rstrip()}{suffix}"

        replaced, count = ADR_STATUS_LINE_RE.subn(_sub, text, count=1)
        if count != 1:
            raise GateError("self-test could not append after-bold status text")
        return replaced

    def rewrite_readme_cell(text: str, row_name: str, new_cell: str) -> str:
        pattern = re.compile(
            rf"(^\| {re.escape(row_name)} \| \*\*)(?P<cell>.+?)(\*\* \|)",
            re.MULTILINE,
        )
        replaced, count = pattern.subn(rf"\g<1>{new_cell}\g<3>", text, count=1)
        if count != 1:
            raise GateError(f"self-test could not rewrite README cell for {row_name}")
        return replaced

    state = copy.deepcopy(baseline)
    state["features"][0]["state"] = "RELEASE_SUPPORTED"
    reject("state above accepted ceiling", state)

    numeric_bool = copy.deepcopy(baseline)
    numeric_bool["module_api_domain"]["schema_version"] = True
    reject("bool substituted for numeric schema version", numeric_bool)

    hil = copy.deepcopy(baseline)
    hil["features"][5]["required_hil"] = False
    hil["features"][5]["state"] = "RELEASE_SUPPORTED"
    hil["features"][5].pop("hil_verified")
    reject("required_hil boolean bypass", hil)

    evidence = copy.deepcopy(baseline)
    evidence["features"][0]["evidence"] = [
        ev("status", "LICENSE", "Apache License")
    ]
    reject("arbitrary existing evidence", evidence)

    false_hil_field = copy.deepcopy(baseline)
    false_hil_field["features"][0]["hil_verified"] = True
    reject("HIL field on non-HIL feature", false_hil_field)

    premature_release_evidence = copy.deepcopy(baseline)
    premature_release_evidence["features"][0]["release_evidence"] = []
    reject("release evidence before release state", premature_release_evidence)

    ceiling = copy.deepcopy(baseline)
    ceiling["features"][5]["state_ceiling"] = "RELEASE_SUPPORTED"
    reject("editable state ceiling", ceiling)

    transitions = copy.deepcopy(baseline)
    transitions["allowed_transitions"]["UNALLOCATED"].append("RELEASE_SUPPORTED")
    reject("direct completion transition", transitions)

    platform = copy.deepcopy(baseline)
    platform["platforms"][2]["required_hil"] = False
    platform["platforms"][2]["state"] = "RELEASE_SUPPORTED"
    platform["platforms"][2].pop("hil_verified")
    reject("platform HIL bypass", platform)

    runner = copy.deepcopy(baseline)
    runner["platforms"][1]["ci_runner"] = "macos-14"
    reject("deprecated/wrong runner", runner)

    workflow = copy.deepcopy(baseline)
    workflow["platforms"][2]["ci_workflow"] = ".github/workflows/ci.yml"
    reject("platform workflow authority drift", workflow)

    version_domain = copy.deepcopy(baseline)
    version_domain["version_domains"]["public_application_data_wire"]["status"] = (
        "RELEASE_SUPPORTED"
    )
    reject("version domain completion drift", version_domain)

    legacy = copy.deepcopy(baseline)
    legacy["legacy_adapters"]["legacy_linkos_lab_wire_1"] = "supported"
    reject("legacy adapter completion drift", legacy)

    # Status-line-only mutations must fail even when the old token remains
    # elsewhere in the same document (no whole-file substring authority).
    adr_status_authorities = (
        (
            "ADR-0017 Proposed overclaim",
            ROOT / "docs/adr/0017-bearer-registry-path-selection.md",
            "Accepted — docs-only false overclaim",
        ),
        (
            "ADR-0017 Proposed underclaim",
            ROOT / "docs/adr/0017-bearer-registry-path-selection.md",
            "UNALLOCATED — docs-only false underclaim",
        ),
        (
            "ADR-0018 Proposed overclaim",
            ROOT / "docs/adr/0018-wifi-bearer.md",
            "RELEASE_SUPPORTED — false overclaim",
        ),
        (
            "ADR-0019 Proposed overclaim",
            ROOT / "docs/adr/0019-route-relay.md",
            "Accepted — false overclaim",
        ),
        (
            "ADR-0020 Proposed overclaim",
            ROOT / "docs/adr/0020-multi-parent.md",
            "Accepted — false overclaim",
        ),
        (
            "ADR-0021 SPEC_ACCEPTED underclaim",
            ROOT / "docs/adr/0021-multi-frame-durable-custody.md",
            "Proposed — false underclaim",
        ),
        (
            "ADR-0021 SPEC_ACCEPTED overclaim",
            ROOT / "docs/adr/0021-multi-frame-durable-custody.md",
            "RELEASE_SUPPORTED — false overclaim",
        ),
        (
            "ADR-0022 SPEC_ACCEPTED overclaim",
            ROOT / "docs/adr/0022-domain-store-schema1-runtime-binding.md",
            "RELEASE_SUPPORTED (design only) — false overclaim",
        ),
        (
            "ADR-0022 SPEC_ACCEPTED underclaim",
            ROOT / "docs/adr/0022-domain-store-schema1-runtime-binding.md",
            "Proposed (design only) — implementation incomplete",
        ),
        (
            "ADR-0022 SPEC_ACCEPTED + RELEASE_SUPPORTED visible",
            ROOT / "docs/adr/0022-domain-store-schema1-runtime-binding.md",
            "SPEC_ACCEPTED (design only) — RELEASE_SUPPORTED pending",
        ),
        (
            "ADR-0010 Accepted underclaim",
            ROOT / "docs/adr/0010-r6-secure-radio-wire.md",
            "Proposed",
        ),
        (
            "ADR-0010 Accepted overclaim",
            ROOT / "docs/adr/0010-r6-secure-radio-wire.md",
            "RELEASE_SUPPORTED",
        ),
        (
            "independent-review status overclaim",
            ROOT
            / "docs/reviews/2026-07-29-domain-store-schema1-spec-accepted.md",
            "SPEC_ACCEPTED review GO — P0=1 / P1=0 / P2=0",
        ),
    )
    for label, path, new_body in adr_status_authorities:
        reject_file_mutation(
            label,
            path,
            lambda text, body=new_body: rewrite_adr_status(text, body),
        )

    readme_path = ROOT / "README.md"
    feature_state = {
        item["id"]: item["state"]
        for item in baseline["features"]
        if isinstance(item, dict) and "id" in item
    }
    for feature_id, row_name in FEATURE_README_ROWS.items():
        current_state = feature_state[feature_id]
        overclaim_cell = (
            "RELEASE_SUPPORTED"
            if current_state != "RELEASE_SUPPORTED"
            else "HIL_VERIFIED"
        )
        # Lowest completion state cannot underclaim by name; force a non-binding cell.
        underclaim_cell = (
            "UNALLOCATED" if current_state != "UNALLOCATED" else "NOT_A_COMPLETION_STATE"
        )
        reject_file_mutation(
            f"README {feature_id} overclaim",
            readme_path,
            lambda text, row=row_name, cell=overclaim_cell: rewrite_readme_cell(
                text, row, cell
            ),
        )
        reject_file_mutation(
            f"README {feature_id} underclaim",
            readme_path,
            lambda text, row=row_name, cell=underclaim_cell: rewrite_readme_cell(
                text, row, cell
            ),
        )

    # Mixed-token / prefix / suffix / second-line / comment-smuggling adversaries.
    # These must fail even when a required token still appears somewhere nearby.
    portable_row = FEATURE_README_ROWS["portable-core-host-runtime"]
    portable_state = feature_state["portable-core-host-runtime"]
    reject_file_mutation(
        "README mixed-token CURRENT / RELEASE_SUPPORTED",
        readme_path,
        lambda text, row=portable_row: rewrite_readme_cell(
            text, row, "CURRENT / RELEASE_SUPPORTED"
        ),
    )
    reject_file_mutation(
        "README mixed-token state / RELEASE_SUPPORTED",
        readme_path,
        lambda text, row=portable_row, state=portable_state: rewrite_readme_cell(
            text, row, f"{state} / RELEASE_SUPPORTED"
        ),
    )
    reject_file_mutation(
        "README visible STATE + RELEASE_SUPPORTED prose",
        readme_path,
        lambda text, row=portable_row, state=portable_state: rewrite_readme_cell(
            text, row, f"{state} — also RELEASE_SUPPORTED"
        ),
    )
    reject_file_mutation(
        "README visible STATE with RELEASE_SUPPORTED",
        readme_path,
        lambda text, row=portable_row, state=portable_state: rewrite_readme_cell(
            text, row, f"{state} with RELEASE_SUPPORTED"
        ),
    )
    reject_file_mutation(
        "README suffix smuggle HOST_CANDIDATE_RELEASE",
        readme_path,
        lambda text, row=portable_row, state=portable_state: rewrite_readme_cell(
            text, row, f"{state}_RELEASE"
        ),
    )
    reject_file_mutation(
        "README prefix smuggle PRE_HOST_CANDIDATE",
        readme_path,
        lambda text, row=portable_row, state=portable_state: rewrite_readme_cell(
            text, row, f"PRE_{state}"
        ),
    )

    adr0017 = ROOT / "docs/adr/0017-bearer-registry-path-selection.md"
    reject_file_mutation(
        "ADR mixed-token Proposed / RELEASE_SUPPORTED",
        adr0017,
        lambda text: rewrite_adr_status(text, "Proposed / RELEASE_SUPPORTED"),
    )
    reject_file_mutation(
        "ADR visible Proposed + RELEASE_SUPPORTED prose",
        adr0017,
        lambda text: rewrite_adr_status(
            text, "Proposed — also RELEASE_SUPPORTED pending"
        ),
    )
    reject_file_mutation(
        "ADR suffix smuggle Proposed_RELEASE",
        adr0017,
        lambda text: rewrite_adr_status(text, "Proposed_RELEASE"),
    )
    reject_file_mutation(
        "ADR prefix smuggle PRE_Proposed",
        adr0017,
        lambda text: rewrite_adr_status(text, "PRE_Proposed"),
    )

    review_path = (
        ROOT / "docs/reviews/2026-07-29-domain-store-schema1-spec-accepted.md"
    )
    reject_file_mutation(
        "independent-review NO-GO with mixed RELEASE_SUPPORTED",
        review_path,
        lambda text: rewrite_adr_status(
            text, "SPEC_ACCEPTED review NO-GO / RELEASE_SUPPORTED — P0=0 / P1=0 / P2=0"
        ),
    )
    reject_file_mutation(
        "independent-review NO-GO structured counts",
        review_path,
        lambda text: rewrite_adr_status(
            text, "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0"
        ),
    )
    reject_file_mutation(
        "independent-review same-line live NO-GO + trailing stale GO",
        review_path,
        lambda text: rewrite_adr_status(
            text,
            "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0 "
            "GO — P0=0 / P1=0 / P2=0",
        ),
    )
    reject_file_mutation(
        "independent-review same-line NO-GO semicolon stale GO",
        review_path,
        lambda text: rewrite_adr_status(
            text,
            "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0; "
            "stale GO — P0=0 / P1=0 / P2=0",
        ),
    )
    reject_file_mutation(
        "independent-review second-line stale P0=0 token",
        review_path,
        lambda text: rewrite_adr_status(
            text, "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0"
        )
        + "\n\nP0=0 / P1=0 / P2=0\n",
    )
    reject_file_mutation(
        "independent-review multiline HTML comment hides GO while live NO-GO",
        review_path,
        lambda text: (
            "<!--\n"
            "状態: **SPEC_ACCEPTED review GO — P0=0 / P1=0 / P2=0**\n"
            "-->\n"
            + rewrite_adr_status(
                text, "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0"
            )
        ),
    )
    reject_file_mutation(
        "independent-review comment-smuggling stale GO counts",
        review_path,
        lambda text: (
            rewrite_adr_status(
                text, "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0"
            )
            + "\n\n<!-- P0=0 / P1=0 / P2=0 -->\n"
            + "<!-- 状態: **SPEC_ACCEPTED review GO — P0=0 / P1=0 / P2=0** -->\n"
        ),
    )
    reject_file_mutation(
        "independent-review in-body stale count smuggle",
        review_path,
        lambda text: rewrite_adr_status(
            text,
            "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0 "
            "(stale note P0=0 / P1=0 / P2=0)",
        ),
    )
    reject_file_mutation(
        "independent-review conflicting multiple live 状態 lines",
        review_path,
        lambda text: (
            rewrite_adr_status(
                text, "SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0"
            )
            + "\n状態: **SPEC_ACCEPTED review GO — P0=0 / P1=0 / P2=0**\n"
        ),
    )
    # P1-1 concrete survivors: after-bold contradictions + indented second lines.
    adr0022 = ROOT / "docs/adr/0022-domain-store-schema1-runtime-binding.md"
    reject_file_mutation(
        "ADR-0022 after-bold live RELEASE_SUPPORTED",
        adr0022,
        lambda text: append_after_bold(text, " — RELEASE_SUPPORTED"),
    )
    reject_file_mutation(
        "ADR-0017 after-bold live RELEASE_SUPPORTED",
        adr0017,
        lambda text: append_after_bold(text, " RELEASE_SUPPORTED"),
    )
    reject_file_mutation(
        "independent-review after-bold live stale NO-GO P0=1",
        review_path,
        lambda text: append_after_bold(
            text, " NO-GO — P0=1 / P1=0 / P2=0"
        ),
    )
    reject_file_mutation(
        "indented second 状態 RELEASE_SUPPORTED",
        adr0022,
        lambda text: text + "\n 状態: **RELEASE_SUPPORTED**\n",
    )
    reject_file_mutation(
        "indented second 状態 NO-GO",
        review_path,
        lambda text: text
        + "\n 状態: **SPEC_ACCEPTED review NO-GO — P0=1 / P1=0 / P2=0**\n",
    )
    # Blockquote claim-like status smuggling (not authoritative locations).
    reject_file_mutation(
        "blockquote > 状態: RELEASE_SUPPORTED",
        adr0022,
        lambda text: text + "\n\n> 状態: **RELEASE_SUPPORTED**\n",
    )
    reject_file_mutation(
        "blockquote > 状態: bare RELEASE_SUPPORTED",
        adr0017,
        lambda text: text + "\n\n> 状態: RELEASE_SUPPORTED\n",
    )
    # Status line moved into a text fence is not authoritative (must reject).
    reject_file_mutation(
        "ADR 状態 moved into fence leaving none live",
        adr0017,
        lambda text: re.sub(
            r"(?m)^[ \t]*状態:\s*\*\*.+?\*\*.*$",
            "```text\n状態: **SPEC_ACCEPTED**\n```",
            text,
            count=1,
        ),
    )
    reject_file_mutation(
        "ADR unique 状態 only inside text code fence",
        adr0022,
        lambda text: re.sub(
            r"(?m)^[ \t]*状態:\s*\*\*.+?\*\*.*$",
            "```text\n状態: **RELEASE_SUPPORTED**\n```",
            text,
            count=1,
        ),
    )

    # Full Apache-2.0 LICENSE bytes authority (one-line stub must reject).
    license_path = ROOT / "LICENSE"
    reject_file_mutation(
        "one-line Apache License stub",
        license_path,
        lambda _text: "Apache License\n",
    )
    reject_file_mutation(
        "LICENSE truncated after header",
        license_path,
        lambda text: "\n".join(text.splitlines()[:5]) + "\n",
    )

    # NOTICE obligations cannot drop third-party pointer.
    notice_path = ROOT / "NOTICE"
    reject_file_mutation(
        "NOTICE missing third-party pointer",
        notice_path,
        lambda text: text.replace("THIRD-PARTY-NOTICES.md", "REMOVED.md"),
    )
    reject_file_mutation(
        "NOTICE negation smuggling with obligation substrings",
        notice_path,
        lambda _text: (
            "Ninlil\n======\n\n"
            "This product does NOT include software developed as part of the Ninlil project.\n"
            "The source code is NOT licensed under the Apache License, Version 2.0.\n"
            "See LICENSE nowhere for the full license text.\n"
            "Not THIRD-PARTY-NOTICES.md.\n"
            "But tokens: Ninlil Apache License, Version 2.0 LICENSE THIRD-PARTY-NOTICES.md\n"
        ),
    )

    # Distribution manifest authority cannot live only in HTML comments.
    dist_path = ROOT / SDK_DISTRIBUTION_MANIFEST_PATH

    def _comment_only_manifest(text: str) -> str:
        # Remove live fenced json authority; leave schema only inside HTML comment.
        live = re.sub(
            r"```json\s*\n.*?```",
            "<!-- " + SDK_DISTRIBUTION_SCHEMA + " moved to comment-only -->",
            text,
            count=1,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if SDK_DISTRIBUTION_SCHEMA not in live:
            live = (
                "<!-- schema: " + SDK_DISTRIBUTION_SCHEMA + " -->\n" + live
            )
        return live

    reject_file_mutation(
        "sdk distribution manifest comment-only authority",
        dist_path,
        _comment_only_manifest,
    )

    invalid_record = copy.deepcopy(valid_record)
    invalid_record["commit"] = "short"
    try:
        check_verification_record(
            invalid_record,
            "invalid evidence record",
            {"esp32s3-esp-idf"},
            "esp32s3-esp-idf",
        )
    except GateError:
        pass
    else:
        raise GateError("self-test mutation was accepted: short evidence commit")

    wrong_subject = copy.deepcopy(valid_record)
    wrong_subject["subject_id"] = "relay"
    try:
        check_verification_record(
            wrong_subject,
            "wrong-subject evidence record",
            {"esp32s3-esp-idf"},
            "esp32s3-esp-idf",
        )
    except GateError:
        pass
    else:
        raise GateError("self-test mutation was accepted: wrong evidence subject")

    impossible_timestamp = copy.deepcopy(valid_record)
    impossible_timestamp["timestamp"] = "2026-99-99T99:99:99Z"
    try:
        check_verification_record(
            impossible_timestamp,
            "impossible-timestamp evidence record",
            {"esp32s3-esp-idf"},
            "esp32s3-esp-idf",
        )
    except GateError:
        pass
    else:
        raise GateError("self-test mutation was accepted: impossible timestamp")

    if _FILE_TEXT_OVERRIDES:
        raise GateError("self-test left in-memory file overlays installed")
    assert_source_metadata_unchanged(meta_before, watched, "self-test complete")
    # Repeated pass must also leave sources untouched.
    meta_mid = snapshot_source_metadata(watched)
    check(load_matrix())
    assert_source_metadata_unchanged(meta_mid, watched, "self-test repeat check")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        if args.command == "check":
            check(load_matrix())
        else:
            self_test()
    except (GateError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"compatibility matrix gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"compatibility matrix gate {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
