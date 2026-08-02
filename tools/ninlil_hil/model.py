"""Closed data model and profile checks for Ninlil HIL evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "ninlil-hil-manifest-v1"
EVENTS_SCHEMA = "ninlil-hil-events-v1"
RESOURCES_SCHEMA = "ninlil-hil-resources-v1"
FAULTS_SCHEMA = "ninlil-hil-faults-v1"
VERDICT_SCHEMA = "ninlil-hil-verdict-v1"
INVENTORY_SCHEMA = "ninlil-hil-inventory-v1"
EVENT_PREFIX = "NINLIL_HIL_EVENT_V1 "
ORIGIN = "LOCAL_PLUGIN_OUTPUT_UNVERIFIED"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SECRET_KEY_RE = re.compile(
    r"(?:authorization|cookie|credential|password|passwd|private.?key|"
    r"secret|session|api.?key|access.?(?:key|token)|refresh.?token|token)",
    re.IGNORECASE,
)
SECRET_TEXT_RES = (
    re.compile(
        r"(?i)\b([a-z0-9_.-]*(?:authorization|cookie|credential|password|"
        r"passwd|private[_-]?key|secret|session|api[_-]?key|"
        r"access[_-]?(?:key|token)|refresh[_-]?token|token)"
        r"[a-z0-9_.-]*)\s*([:=])\s*"
        r"(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@"),
)
HEADER_SECRET_RE = re.compile(r"(?im)^(authorization|cookie)\s*:[^\r\n]*")
JSON_SECRET_RE = re.compile(
    r'(?i)("(?:[^"]*(?:authorization|cookie|credential|password|passwd|'
    r'private.?key|secret|session|api.?key|access.?(?:key|token)|'
    r'refresh.?token|token)'
    r'[^"]*)"\s*:\s*)("(?:\\.|[^"])*"|[^,}\s]+)'
)
ATOMIC_EVENTS = {
    "D0": "DIR_BEFORE_ERASE",
    "D1": "DIR_BEFORE_WRITE",
    "D2": "DIR_BEFORE_SEAL",
    "S0": "DATA_BEFORE_ERASE",
    "S1": "DATA_BEFORE_WRITE",
    "S2": "DATA_AFTER_SYNC_BEFORE_RETURN",
}
SNAPSHOT_DOMAIN = b"NINLIL-HIL-SNAPSHOT-V1"
DIRECTORY_DOMAIN = b"NINLIL-HIL-DIRECTORY-V1"


class EvidenceError(ValueError):
    """Input or evidence violated a closed HIL contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def require_exact_keys(
    value: Any, required: set[str], optional: set[str], where: str
) -> dict[str, Any]:
    require(isinstance(value, dict), f"{where} must be an object")
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    require(not missing, f"{where} missing keys: {sorted(missing)}")
    require(not extra, f"{where} has unknown keys: {sorted(extra)}")
    return value


def require_id(value: Any, where: str) -> str:
    require(isinstance(value, str) and ID_RE.fullmatch(value) is not None,
            f"{where} must be a safe identifier")
    return value


def require_text(value: Any, where: str, maximum: int = 256) -> str:
    require(
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and "\x00" not in value,
        f"{where} must be non-empty text no longer than {maximum}",
    )
    return value


def require_exact_int(value: Any, where: str, *, minimum: int = 0,
                      maximum: int | None = None) -> int:
    """Require a JSON integer without accepting Python's bool subtype."""
    require(isinstance(value, int) and not isinstance(value, bool),
            f"{where} must be an integer")
    require(value >= minimum, f"{where} is below minimum")
    if maximum is not None:
        require(value <= maximum, f"{where} exceeds maximum")
    return value


def validate_json_value(
    value: Any, where: str, depth: int = 0, *, reject_secret_keys: bool = True
) -> None:
    require(depth <= 12, f"{where} exceeds maximum nesting")
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return
    if isinstance(value, float):
        require(math.isfinite(value), f"{where} contains non-finite number")
        return
    if isinstance(value, str):
        require(len(value) <= 4096 and "\x00" not in value,
                f"{where} contains invalid/oversized text")
        return
    if isinstance(value, list):
        require(len(value) <= 256, f"{where} array is too large")
        for index, item in enumerate(value):
            validate_json_value(
                item, f"{where}[{index}]", depth + 1,
                reject_secret_keys=reject_secret_keys
            )
        return
    if isinstance(value, dict):
        require(len(value) <= 256, f"{where} object is too large")
        for key, item in value.items():
            require_text(key, f"{where} key", 128)
            if reject_secret_keys:
                require(
                    SECRET_KEY_RE.search(key) is None,
                    f"{where} contains forbidden secret-like key {key!r}",
                )
            validate_json_value(
                item, f"{where}.{key}", depth + 1,
                reject_secret_keys=reject_secret_keys
            )
        return
    raise EvidenceError(f"{where} contains unsupported JSON value")


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = require_exact_keys(
        value,
        {
            "schema", "campaign_id", "run_id", "profile", "source",
            "resources", "cases", "attestation",
        },
        set(),
        "manifest",
    )
    require(manifest["schema"] == MANIFEST_SCHEMA, "unsupported manifest schema")
    require_id(manifest["campaign_id"], "campaign_id")
    require_id(manifest["run_id"], "run_id")
    require(
        manifest["profile"]
        in {"esp-storage-atomic-v1", "esp-storage-namespace-v1", "generic-hil-v1"},
        "unsupported HIL profile",
    )

    source = require_exact_keys(
        manifest["source"],
        {
            "repository_commit", "tree_state", "firmware_sha256",
            "firmware_build_id", "idf_version",
        },
        set(),
        "source",
    )
    require(
        isinstance(source["repository_commit"], str)
        and COMMIT_RE.fullmatch(source["repository_commit"]) is not None,
        "source.repository_commit must be lowercase 40/64 hex",
    )
    require(source["tree_state"] in {"clean", "dirty"}, "invalid tree_state")
    require(
        isinstance(source["firmware_sha256"], str)
        and SHA256_RE.fullmatch(source["firmware_sha256"]) is not None,
        "source.firmware_sha256 must be lowercase SHA-256",
    )
    require_text(source["firmware_build_id"], "source.firmware_build_id")
    require_text(source["idf_version"], "source.idf_version")

    resources = manifest["resources"]
    require(isinstance(resources, list) and 1 <= len(resources) <= 64,
            "resources must contain 1..64 entries")
    resource_ids: set[str] = set()
    for index, raw in enumerate(resources):
        resource = require_exact_keys(
            raw,
            {"resource_id", "kind", "identity", "verification", "attributes"},
            set(),
            f"resources[{index}]",
        )
        resource_id = require_id(resource["resource_id"], "resource_id")
        require(resource_id not in resource_ids, f"duplicate resource {resource_id}")
        resource_ids.add(resource_id)
        require(
            resource["kind"] in {
                "target_board", "storage_media", "power_fixture", "serial_link",
                "firmware", "host", "other",
            },
            f"invalid resource kind for {resource_id}",
        )
        require_text(resource["identity"], f"resource {resource_id} identity")
        require(
            resource["verification"] == "UNVERIFIED_DECLARATION",
            "manifest resources cannot claim verified identity",
        )
        require(isinstance(resource["attributes"], dict),
                f"resource {resource_id} attributes must be an object")
        require(len(resource["attributes"]) <= 64,
                f"resource {resource_id} attributes exceed capacity")
        validate_json_value(resource["attributes"], f"resource {resource_id} attributes")

    cases = manifest["cases"]
    require(isinstance(cases, list) and 1 <= len(cases) <= 4096,
            "cases must contain 1..4096 entries")
    case_ids: set[str] = set()
    for index, raw in enumerate(cases):
        case = require_exact_keys(
            raw, {"case_id", "phase", "expected", "allowed"}, set(),
            f"cases[{index}]"
        )
        case_id = require_id(case["case_id"], "case_id")
        require(case_id not in case_ids, f"duplicate case {case_id}")
        case_ids.add(case_id)
        require_id(case["phase"], f"case {case_id} phase")
        require(isinstance(case["expected"], dict),
                f"case {case_id} expected must be an object")
        require(isinstance(case["allowed"], dict),
                f"case {case_id} allowed must be an object")
        require(not (set(case["expected"]) & set(case["allowed"])),
                f"case {case_id} expected/allowed keys overlap")
        validate_json_value(case["expected"], f"case {case_id} expected")
        validate_json_value(case["allowed"], f"case {case_id} allowed")
        for key, choices in case["allowed"].items():
            require_text(key, f"case {case_id} allowed key", 128)
            require(isinstance(choices, list) and 1 <= len(choices) <= 128,
                    f"case {case_id} allowed.{key} must be a non-empty array")

    attestation = require_exact_keys(
        manifest["attestation"], {"requested", "evidence_origin"}, set(),
        "attestation"
    )
    require(
        attestation["requested"] in {"EVIDENCE_ONLY", "FULL_CANDIDATE_REVIEW"},
        "invalid attestation request",
    )
    require(
        attestation["evidence_origin"] == ORIGIN,
        "v1 accepts only explicitly unverified local plugin output",
    )
    validate_profile_manifest(manifest)
    return manifest


def validate_profile_manifest(manifest: dict[str, Any]) -> None:
    profile = manifest["profile"]
    if profile == "esp-storage-atomic-v1":
        for case in manifest["cases"]:
            scenario = case["expected"].get("scenario")
            require(scenario in ATOMIC_EVENTS,
                    f"atomic case {case['case_id']} has invalid scenario")
            require(
                case["expected"].get("event") == ATOMIC_EVENTS[scenario],
                f"atomic case {case['case_id']} has wrong event",
            )
            delay = case["expected"].get("delay_ms")
            require(
                isinstance(delay, (int, float))
                and not isinstance(delay, bool)
                and math.isfinite(float(delay))
                and 0.0 <= float(delay) <= 5000.0,
                f"atomic case {case['case_id']} has invalid delay_ms",
            )
            require(case["allowed"].get("state") == ["OLD", "NEW"],
                    f"atomic case {case['case_id']} must allow OLD/NEW")
    elif profile == "esp-storage-namespace-v1":
        required_phases = [
            "AB_CREATE_A", "AB_REBOOT_A", "AB_CREATE_B", "AB_REBOOT_B",
            "BA_CREATE_B", "BA_REBOOT_B", "BA_CREATE_A", "BA_REBOOT_A",
        ]
        phases = [case["phase"] for case in manifest["cases"]]
        require(phases == required_phases,
                "namespace profile requires the ordered AB/BA eight-phase campaign")
        phase_contract = {
            "AB_CREATE_A": ("AB", "CREATE_VERIFY", "NS-A", False, True),
            "AB_REBOOT_A": ("AB", "COLD_REBOOT_VERIFY", None, True, False),
            "AB_CREATE_B": ("AB", "CREATE_VERIFY", "NS-B", False, False),
            "AB_REBOOT_B": ("AB", "COLD_REBOOT_VERIFY", None, True, False),
            "BA_CREATE_B": ("BA", "CREATE_VERIFY", "NS-B", False, True),
            "BA_REBOOT_B": ("BA", "COLD_REBOOT_VERIFY", None, True, False),
            "BA_CREATE_A": ("BA", "CREATE_VERIFY", "NS-A", False, False),
            "BA_REBOOT_A": ("BA", "COLD_REBOOT_VERIFY", None, True, False),
        }
        for case in manifest["cases"]:
            campaign, action, created, boot_changed, erased = phase_contract[
                case["phase"]
            ]
            required_expected = {
                "campaign": campaign,
                "action": action,
                "created_namespace": created,
                "cold_boot_nonce_changed": boot_changed,
                "partition_erased_before_phase": erased,
                "unexpected_namespace": False,
            }
            for key, value in required_expected.items():
                require(
                    case["expected"].get(key) == value,
                    f"namespace phase {case['phase']} must pin {key}={value!r}",
                )
            require(
                set(case["allowed"]) == {"directory_indices", "snapshots"},
                f"namespace phase {case['phase']} must allow only indices/snapshots",
            )


def validate_plugin_event(value: Any) -> dict[str, Any]:
    event = require_exact_keys(
        value, {"event_id", "case_id", "outcome", "observed"}, set(),
        "plugin event"
    )
    require_id(event["event_id"], "event_id")
    require_id(event["case_id"], "event case_id")
    require(event["outcome"] in {"PASS", "FAIL", "ERROR"}, "invalid event outcome")
    require(isinstance(event["observed"], dict), "event observed must be an object")
    validate_json_value(event["observed"], "event observed")
    return event


def canonical_record(key: bytes, value: bytes) -> bytes:
    return len(key).to_bytes(2, "big") + key + len(value).to_bytes(4, "big") + value


def expected_data_digest(state: str) -> str:
    if state == "OLD":
        records = ((b"a", b"old-A"), (b"b", b"old-B"))
    elif state == "NEW":
        records = ((b"a", b"new-A-long"), (b"c", b"new-C"))
    else:
        raise EvidenceError(f"invalid atomic state {state!r}")
    data = SNAPSHOT_DOMAIN + bytes((len(records),))
    data += b"".join(canonical_record(key, value) for key, value in records)
    return hashlib.sha256(data).hexdigest()


def expected_atomic_digest(scenario: str, state: str) -> str:
    if scenario.startswith("S"):
        return expected_data_digest(state)
    if scenario.startswith("D"):
        data = (
            DIRECTORY_DOMAIN + scenario.encode("ascii")
            + bytes((1 if state == "OLD" else 2,))
            + bytes.fromhex(expected_data_digest("OLD"))
        )
        return hashlib.sha256(data).hexdigest()
    raise EvidenceError(f"invalid atomic scenario {scenario!r}")


def compare_case(
    profile: str, case: dict[str, Any], event: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    observed = event["observed"]
    expected = case["expected"]
    allowed = case["allowed"]
    expected_keys = set(expected) | set(allowed)
    if set(observed) != expected_keys:
        errors.append(
            f"observed keys differ: got {sorted(observed)}, "
            f"expected {sorted(expected_keys)}"
        )
        return errors
    for key, expected_value in expected.items():
        if not json_value_equal_exact(observed.get(key), expected_value):
            errors.append(f"{key} mismatch")
    for key, choices in allowed.items():
        if not any(
            json_value_equal_exact(observed.get(key), choice)
            for choice in choices
        ):
            errors.append(f"{key} is outside allowed set")
    if profile == "esp-storage-atomic-v1" and not errors:
        digest = observed.get("digest")
        scenario = observed.get("scenario")
        state = observed.get("state")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            errors.append("digest is not canonical SHA-256")
        elif digest != expected_atomic_digest(scenario, state):
            errors.append("digest does not match the canonical OLD/NEW snapshot")
    return errors


def json_value_equal_exact(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int numeric coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (
            set(left) == set(right)
            and all(json_value_equal_exact(left[key], right[key]) for key in left)
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            json_value_equal_exact(a, b) for a, b in zip(left, right)
        )
    return bool(left == right)


def validate_namespace_campaign(events: list[dict[str, Any]]) -> list[str]:
    """Cross-check stable indices and exact NS-A/NS-B snapshots."""
    errors: list[str] = []
    expected_values = {
        "NS-A": {"a": "A-old", "b": "A-stable", "c": None},
        "NS-B": {"a": "B-stable", "b": None, "c": "B-new"},
    }
    by_campaign: dict[str, list[dict[str, Any]]] = {"AB": [], "BA": []}
    for event in events:
        observed = event["observed"]
        campaign = observed.get("campaign")
        if campaign not in by_campaign:
            errors.append(f"{event['case_id']}: invalid namespace campaign")
            continue
        by_campaign[campaign].append(observed)
        snapshots = observed.get("snapshots")
        indices = observed.get("directory_indices")
        if not isinstance(snapshots, dict) or not isinstance(indices, dict):
            errors.append(f"{event['case_id']}: missing snapshots/indices")
            continue
        if (
            any(
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index > 3
                for index in indices.values()
            )
            or set(indices) != set(snapshots)
        ):
            errors.append(f"{event['case_id']}: invalid directory index map")
            continue
        if len(set(indices.values())) != len(indices):
            errors.append(f"{event['case_id']}: duplicate directory index")
        for namespace, snapshot in snapshots.items():
            if namespace not in expected_values or not isinstance(snapshot, dict):
                errors.append(f"{event['case_id']}: unexpected namespace")
                continue
            expected = expected_values[namespace]
            if snapshot != {
                "entry_count": 2,
                "logical_bytes": 47,
                "values": expected,
            }:
                errors.append(f"{event['case_id']}: wrong {namespace} snapshot")
        if observed.get("unexpected_namespace") is not False:
            errors.append(f"{event['case_id']}: unexpected namespace not disproved")
        if observed.get("action") == "COLD_REBOOT_VERIFY":
            if observed.get("cold_boot_nonce_changed") is not True:
                errors.append(f"{event['case_id']}: cold boot identity did not change")
    for campaign, observations in by_campaign.items():
        stable: dict[str, Any] = {}
        for observed in observations:
            for namespace, index in observed.get("directory_indices", {}).items():
                if namespace in stable and stable[namespace] != index:
                    errors.append(f"{campaign}: {namespace} directory index drift")
                stable[namespace] = index
    return errors


def redact_text(text: str) -> str:
    # Header credentials are line-oriented, not token-oriented: redact the
    # whole value (for example, ``Authorization: Basic <base64>``).
    redacted = HEADER_SECRET_RE.sub(r"\1:[REDACTED]", text)
    redacted = JSON_SECRET_RE.sub(r'\1"[REDACTED]"', redacted)
    for pattern in SECRET_TEXT_RES:
        if "Bearer" in pattern.pattern:
            redacted = pattern.sub("Bearer [REDACTED]", redacted)
        elif "https?" in pattern.pattern:
            redacted = pattern.sub(r"\1[REDACTED]@", redacted)
        else:
            redacted = pattern.sub(r"\1\2[REDACTED]", redacted)
    return redacted


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def load_json_file(path: Path, maximum: int = 4 * 1024 * 1024) -> Any:
    require(path.is_file() and not path.is_symlink(), f"not a regular file: {path}")
    size = path.stat().st_size
    require(size <= maximum, f"JSON file is too large: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot parse JSON {path}: {error}") from error
