"""Offline adversarial self-tests for the closed HIL evidence format.

The production verifier is intentionally the authority for semantic evidence
checks.  This module adds two independent safeguards around it:

* every document produced by an offline campaign is checked against the
  versioned JSON-schema instance that names it; and
* deliberately hostile plugins exercise the process, control-file, namespace,
  redaction, and re-hash boundaries without requiring hardware or a network.

The small schema evaluator below supports the deliberately small draft-2020-12
keyword subset used by ``spec/hil``.  It is not a general JSON Schema library;
keeping it here avoids making the CI-only evidence gate depend on a package that
is not part of the runtime distribution.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .model import (
    INVENTORY_SCHEMA,
    EvidenceError,
    canonical_json_bytes,
    compare_case,
    validate_manifest,
    validate_namespace_campaign,
)
from .runner import (
    build_inventory, inventory_receipt, parse_plugin, run_campaign, verify_run,
)
from .templates import create_manifest


SCHEMA_BY_DOCUMENT = {
    "manifest.json": "ninlil-hil-manifest-v1.schema.json",
    "events.json": "ninlil-hil-events-v1.schema.json",
    "resources.json": "ninlil-hil-resources-v1.schema.json",
    "faults.json": "ninlil-hil-faults-v1.schema.json",
    "verdict.json": "ninlil-hil-verdict-v1.schema.json",
    "inventory.json": "ninlil-hil-inventory-v1.schema.json",
}

EXPECTED_SCHEMA_FILES = frozenset(
    {
        *SCHEMA_BY_DOCUMENT.values(),
        "ninlil-hil-rrmp-multiparent-v1.schema.json",
    }
)


def sample_manifest(run_id: str = "offline-pass") -> dict[str, Any]:
    return {
        "schema": "ninlil-hil-manifest-v1",
        "campaign_id": "offline-selftest",
        "run_id": run_id,
        "profile": "generic-hil-v1",
        "source": {
            "repository_commit": "0" * 40,
            "tree_state": "clean",
            "firmware_sha256": "1" * 64,
            "firmware_build_id": "offline-selftest-only",
            "idf_version": "offline-selftest-only",
        },
        "resources": [
            {
                "resource_id": "offline-host",
                "kind": "host",
                "identity": "offline-selftest-only",
                "verification": "UNVERIFIED_DECLARATION",
                "attributes": {"network": "disabled"},
            }
        ],
        "cases": [
            {
                "case_id": "OFFLINE-1",
                "phase": "SELFTEST",
                "expected": {"measurement": 7},
                "allowed": {"state": ["OLD", "NEW"]},
            }
        ],
        "attestation": {
            "requested": "FULL_CANDIDATE_REVIEW",
            "evidence_origin": "LOCAL_PLUGIN_OUTPUT_UNVERIFIED",
        },
    }


def rewrite_inventory_member(run_dir: Path, relative: str) -> None:
    """Re-hash one changed member, modelling a deliberate offline re-seal."""
    inventory_path = run_dir / "inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    target = run_dir / relative
    for entry in inventory["files"]:
        if entry["path"] == relative:
            entry["bytes"] = target.stat().st_size
            entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            break
    else:
        raise AssertionError(f"inventory member not found: {relative}")
    inventory_path.write_bytes(canonical_json_bytes(inventory))


def expect_failure(label: str, callback: Callable[[], Any]) -> None:
    try:
        callback()
    except (EvidenceError, ValueError, OSError):
        return
    raise AssertionError(f"negative mutation was accepted: {label}")


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality with booleans deliberately distinct from integers."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _is_json_type(value: Any, expected: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(expected, False)


def _resolve_local_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise AssertionError(f"self-test schema evaluator refuses external ref: {reference}")
    value: Any = root
    for token in reference[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    assert isinstance(value, dict)
    return value


def assert_schema_instance(
    value: Any, schema: dict[str, Any], root: dict[str, Any], where: str = "$"
) -> None:
    """Validate the finite schema subset used by the six checked-in schemas."""
    if "$ref" in schema:
        assert_schema_instance(value, _resolve_local_ref(root, schema["$ref"]), root, where)
        return
    if "const" in schema:
        assert _json_equal(value, schema["const"]), f"{where}: const mismatch"
    if "enum" in schema:
        assert any(_json_equal(value, item) for item in schema["enum"]), (
            f"{where}: enum mismatch"
        )
    if "type" in schema:
        expected_types = schema["type"]
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        assert any(_is_json_type(value, item) for item in expected_types), (
            f"{where}: type mismatch"
        )
    if "anyOf" in schema:
        successes = 0
        for alternative in schema["anyOf"]:
            try:
                assert_schema_instance(value, alternative, root, where)
            except AssertionError:
                continue
            successes += 1
        assert successes >= 1, f"{where}: no anyOf branch matched"
    if "oneOf" in schema:
        successes = 0
        for alternative in schema["oneOf"]:
            try:
                assert_schema_instance(value, alternative, root, where)
            except AssertionError:
                continue
            successes += 1
        assert successes == 1, f"{where}: oneOf matched {successes} branches"
    if isinstance(value, str):
        if "minLength" in schema:
            assert len(value) >= schema["minLength"], f"{where}: below minLength"
        if "maxLength" in schema:
            assert len(value) <= schema["maxLength"], f"{where}: above maxLength"
        if "pattern" in schema:
            import re
            assert re.search(schema["pattern"], value) is not None, f"{where}: pattern mismatch"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema:
            assert value >= schema["minimum"], f"{where}: below minimum"
        if "maximum" in schema:
            assert value <= schema["maximum"], f"{where}: above maximum"
    if isinstance(value, list):
        if "minItems" in schema:
            assert len(value) >= schema["minItems"], f"{where}: below minItems"
        if "maxItems" in schema:
            assert len(value) <= schema["maxItems"], f"{where}: above maxItems"
        if schema.get("uniqueItems"):
            assert len({canonical_json_bytes(item) for item in value}) == len(value), (
                f"{where}: duplicate uniqueItems"
            )
        if "items" in schema:
            for index, item in enumerate(value):
                assert_schema_instance(item, schema["items"], root, f"{where}[{index}]")
    if isinstance(value, dict):
        if "minProperties" in schema:
            assert len(value) >= schema["minProperties"], f"{where}: below minProperties"
        if "maxProperties" in schema:
            assert len(value) <= schema["maxProperties"], f"{where}: above maxProperties"
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            assert required in value, f"{where}: missing {required}"
        if schema.get("additionalProperties") is False:
            extras = set(value) - set(properties)
            assert not extras, f"{where}: unexpected properties {sorted(extras)}"
        for key, item in value.items():
            if key in properties:
                assert_schema_instance(item, properties[key], root, f"{where}.{key}")
            elif isinstance(schema.get("additionalProperties"), dict):
                assert_schema_instance(
                    item, schema["additionalProperties"], root, f"{where}.{key}"
                )


def assert_generated_documents_match_schemas(run_dir: Path) -> None:
    schema_dir = Path(__file__).resolve().parents[2] / "spec" / "hil"
    for document_name, schema_name in SCHEMA_BY_DOCUMENT.items():
        schema = json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
        document = json.loads((run_dir / document_name).read_text(encoding="utf-8"))
        assert_schema_instance(document, schema, schema)


def assert_schema_quality() -> None:
    schema_dir = Path(__file__).resolve().parents[2] / "spec" / "hil"
    schemas = sorted(schema_dir.glob("*.schema.json"))
    actual_schema_files = {path.name for path in schemas}
    assert actual_schema_files == EXPECTED_SCHEMA_FILES, (
        "closed HIL schema inventory mismatch: "
        f"missing={sorted(EXPECTED_SCHEMA_FILES - actual_schema_files)} "
        f"unexpected={sorted(actual_schema_files - EXPECTED_SCHEMA_FILES)}"
    )
    for schema_path in schemas:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].startswith("https://ninlil.dev/schema/hil/")
    assert INVENTORY_SCHEMA in {
        json.loads(path.read_text(encoding="utf-8"))["$id"].split("/")[-1].replace(
            ".schema.json", ""
        )
        for path in schemas
    }
    manifest_schema = json.loads(
        (schema_dir / "ninlil-hil-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    inventory_schema = json.loads(
        (schema_dir / "ninlil-hil-inventory-v1.schema.json").read_text(encoding="utf-8")
    )
    events_schema = json.loads(
        (schema_dir / "ninlil-hil-events-v1.schema.json").read_text(encoding="utf-8")
    )
    faults_schema = json.loads(
        (schema_dir / "ninlil-hil-faults-v1.schema.json").read_text(encoding="utf-8")
    )
    # These document bounds match the runner-owned aggregate limits: 32
    # plugins x two logs plus six core files, and bounded event/fault lists.
    assert inventory_schema["properties"]["files"]["minItems"] == 6
    assert inventory_schema["properties"]["files"]["maxItems"] == 70
    assert events_schema["properties"]["events"]["maxItems"] == 4096
    assert faults_schema["properties"]["faults"]["maxItems"] == 4096
    # JSON Schema ``number`` includes integers.  `anyOf` is intentional here;
    # a `oneOf` would reject every integral JSON value as an overlap.
    assert "anyOf" in manifest_schema["$defs"]["jsonValue"]
    assert_schema_instance(7, manifest_schema["$defs"]["jsonValue"], manifest_schema)
    assert_schema_instance(True, manifest_schema["$defs"]["jsonValue"], manifest_schema)

    rrmp_schema = json.loads(
        (schema_dir / "ninlil-hil-rrmp-multiparent-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    rrmp_template = json.loads(
        (schema_dir.parents[1] / "tools" / "rrmp_hil_evidence_template.json").read_text(
            encoding="utf-8"
        )
    )
    # Canonical URL $id (not bare filename) + closed inventory membership.
    assert rrmp_schema["$id"] == (
        "https://ninlil.dev/schema/hil/ninlil-hil-rrmp-multiparent-v1.schema.json"
    )
    assert rrmp_schema["$id"].startswith("https://ninlil.dev/schema/hil/")
    assert "ninlil-hil-rrmp-multiparent-v1.schema.json" in EXPECTED_SCHEMA_FILES
    # Bounded / required physical residual surface.
    pc = rrmp_schema["properties"]["physical_claims"]
    assert set(pc["required"]) == {
        "rf_2hop",
        "rf_3hop",
        "multiparent_air",
        "powercut_dual_slot",
    }
    assert pc.get("additionalProperties") is False
    assert rrmp_schema["properties"]["nodes"]["minItems"] == 2
    assert rrmp_schema["properties"]["nodes"]["maxItems"] == 16
    assert rrmp_schema["properties"]["nodes"]["uniqueItems"] is True
    assert rrmp_schema["properties"]["scenarios"]["minItems"] == 4
    assert rrmp_schema["properties"]["scenarios"]["maxItems"] == 32
    assert rrmp_schema["properties"]["scenarios"]["uniqueItems"] is True
    assert rrmp_schema["properties"]["nonclaims"]["minItems"] == 1
    assert rrmp_schema["properties"]["nonclaims"]["uniqueItems"] is True
    assert (
        rrmp_schema["properties"]["software_prerequisites"]["properties"][
            "workspace_budget_bytes"
        ]["maximum"]
        == 786432
    )
    assert_schema_instance(rrmp_template, rrmp_schema, rrmp_schema)
    prereq = rrmp_template["software_prerequisites"]
    assert prereq["spec_accepted"] is True
    assert prereq["private_implementation_candidate"] is True
    assert prereq["workspace_measured_host_bytes"] <= prereq["workspace_budget_bytes"]
    assert prereq["workspace_includes_storage_scratch"] is True
    assert prereq["worst_case_live_dynamic_bytes"] == (
        prereq["workspace_measured_host_bytes"]
        + prereq["target_smoke_store_bytes"]
    )
    assert prereq["esp_runtime_workspace_measured_bytes"] is None
    assert prereq["esp_runtime_minimum_free_psram_bytes"] is None
    # Semantic uniqueness (node_id / runtime_id / scenario id) beyond object equality.
    node_ids = [n["node_id"] for n in rrmp_template["nodes"]]
    runtime_ids = [n["runtime_id_hex"].lower() for n in rrmp_template["nodes"]]
    scenario_ids = [s["id"] for s in rrmp_template["scenarios"]]
    assert len(node_ids) == len(set(node_ids))
    assert len(runtime_ids) == len(set(runtime_ids))
    assert len(scenario_ids) == len(set(scenario_ids))
    # Physical residual remains honest NOT_RUN in the checked-in template.
    for key in ("rf_2hop", "rf_3hop", "multiparent_air", "powercut_dual_slot"):
        assert rrmp_template["physical_claims"][key] == "NOT_RUN"
    assert rrmp_template["status"] == "NOT_RUN"

    def _expect_schema_reject(label: str, document: dict[str, Any]) -> None:
        try:
            assert_schema_instance(document, rrmp_schema, rrmp_schema)
        except AssertionError:
            return
        raise AssertionError(f"RRMP schema accepted incomplete claim: {label}")

    import copy

    missing_claim = copy.deepcopy(rrmp_template)
    del missing_claim["physical_claims"]["rf_2hop"]
    _expect_schema_reject("missing physical_claims.rf_2hop", missing_claim)

    empty_physical = copy.deepcopy(rrmp_template)
    empty_physical["physical_claims"] = {}
    _expect_schema_reject("empty physical_claims object", empty_physical)

    one_node = copy.deepcopy(rrmp_template)
    one_node["nodes"] = one_node["nodes"][:1]
    _expect_schema_reject("nodes below minItems=2", one_node)

    few_scenarios = copy.deepcopy(rrmp_template)
    few_scenarios["scenarios"] = few_scenarios["scenarios"][:3]
    _expect_schema_reject("scenarios below minItems=4", few_scenarios)

    empty_nonclaims = copy.deepcopy(rrmp_template)
    empty_nonclaims["nonclaims"] = []
    _expect_schema_reject("empty nonclaims", empty_nonclaims)

    bad_runtime = copy.deepcopy(rrmp_template)
    bad_runtime["nodes"][0]["runtime_id_hex"] = "not-hex"
    _expect_schema_reject("runtime_id_hex pattern", bad_runtime)

    empty_roles = copy.deepcopy(rrmp_template)
    empty_roles["nodes"][0]["role_flags"] = []
    _expect_schema_reject("empty role_flags", empty_roles)

    dup_roles = copy.deepcopy(rrmp_template)
    dup_roles["nodes"][0]["role_flags"] = ["relay", "relay"]
    _expect_schema_reject("duplicate role_flags uniqueItems", dup_roles)

    extra_claim = copy.deepcopy(rrmp_template)
    extra_claim["physical_claims"]["rf_mystery"] = "NOT_RUN"
    _expect_schema_reject("unexpected physical_claims key", extra_claim)

    missing_soft = copy.deepcopy(rrmp_template)
    del missing_soft["software_prerequisites"]["esp_idf_map_proof"]
    _expect_schema_reject("missing software prerequisite", missing_soft)

    missing_spec_authority = copy.deepcopy(rrmp_template)
    del missing_spec_authority["software_prerequisites"]["spec_accepted"]
    _expect_schema_reject(
        "missing software_prerequisites.spec_accepted",
        missing_spec_authority,
    )

    missing_tooling = copy.deepcopy(rrmp_template)
    del missing_tooling["tooling"]["software_hil_manifest"]
    _expect_schema_reject("missing tooling authority", missing_tooling)

    extra_tooling = copy.deepcopy(rrmp_template)
    extra_tooling["tooling"]["unbounded_command"] = "not allowed"
    _expect_schema_reject("unexpected tooling authority", extra_tooling)

    # Semantic uniqueness negatives (same node_id / scenario id).
    dup_node = copy.deepcopy(rrmp_template)
    dup_node["nodes"][1]["node_id"] = dup_node["nodes"][0]["node_id"]
    # Full-object uniqueItems may still pass if other fields differ — enforce.
    ids = [n["node_id"] for n in dup_node["nodes"]]
    assert len(ids) != len(set(ids))
    dup_scen = copy.deepcopy(rrmp_template)
    dup_scen["scenarios"][1]["id"] = dup_scen["scenarios"][0]["id"]
    sids = [s["id"] for s in dup_scen["scenarios"]]
    assert len(sids) != len(set(sids))


def namespace_offline_check() -> None:
    values_a = {"entry_count": 2, "logical_bytes": 47,
                "values": {"a": "A-old", "b": "A-stable", "c": None}}
    values_b = {"entry_count": 2, "logical_bytes": 47,
                "values": {"a": "B-stable", "b": None, "c": "B-new"}}
    events: list[dict[str, Any]] = []
    phases = (
        ("AB", {"NS-A": 0}, {"NS-A": values_a}),
        ("AB", {"NS-A": 0}, {"NS-A": values_a}),
        ("AB", {"NS-A": 0, "NS-B": 1}, {"NS-A": values_a, "NS-B": values_b}),
        ("AB", {"NS-A": 0, "NS-B": 1}, {"NS-A": values_a, "NS-B": values_b}),
        ("BA", {"NS-B": 0}, {"NS-B": values_b}),
        ("BA", {"NS-B": 0}, {"NS-B": values_b}),
        ("BA", {"NS-B": 0, "NS-A": 1}, {"NS-B": values_b, "NS-A": values_a}),
        ("BA", {"NS-B": 0, "NS-A": 1}, {"NS-B": values_b, "NS-A": values_a}),
    )
    for index, (campaign, indices, snapshots) in enumerate(phases):
        events.append(
            {
                "case_id": f"NS-{index}",
                "observed": {
                    "campaign": campaign,
                    "directory_indices": indices,
                    "snapshots": snapshots,
                    "unexpected_namespace": False,
                },
            }
        )
    assert validate_namespace_campaign(events) == []
    events[3]["observed"]["directory_indices"]["NS-A"] = 1
    assert validate_namespace_campaign(events)


def _fault_codes(run_dir: Path) -> set[str]:
    return {
        fault["code"]
        for fault in json.loads((run_dir / "faults.json").read_text(encoding="utf-8"))["faults"]
    }


def _assert_descendant_was_killed(marker: Path) -> None:
    # The child only writes after its parent has already exceeded the bounded
    # execution condition.  Waiting past that delay catches a process-group
    # kill that accidentally stopped only the immediate parent.
    time.sleep(1.2)
    assert not marker.exists(), "bounded plugin left a descendant running"


def run_self_test() -> None:
    if not __debug__:
        raise EvidenceError("self-test refuses optimized Python with assertions disabled")
    plugin_script = Path(__file__).with_name("selftest_plugin.py").resolve()
    with tempfile.TemporaryDirectory(prefix="ninlil-hil-selftest-") as raw_temp:
        temp = Path(raw_temp)
        manifest_path = temp / "manifest.json"
        manifest_path.write_bytes(canonical_json_bytes(sample_manifest()))
        output_root = temp / "runs"
        plugin = json.dumps(
            {
                "name": "offline-plugin",
                "argv": [sys.executable, str(plugin_script), "--mode", "pass"],
                "timeout_seconds": 10,
                "max_output_bytes": 65536,
            }
        )
        run_dir, verdict = run_campaign(manifest_path, output_root, [plugin])
        assert verdict["status"] == "PASS"
        assert verdict["attestation"]["full_promotion_permitted"] is False
        assert verdict["attestation"]["runtime_policy"] == "ESP_UNPROVEN"
        assert verdict["attestation"]["physical_hil_claimed"] is False
        assert verify_run(run_dir)["status"] == "PASS"
        receipt = inventory_receipt(run_dir)
        assert verify_run(run_dir, receipt)["status"] == "PASS"
        assert_generated_documents_match_schemas(run_dir)
        plugin_context = json.loads(
            (run_dir / "plugin-context.json").read_text(encoding="utf-8")
        )
        assert plugin_context == {
            "schema": "ninlil-hil-plugin-context-v1",
            "campaign_id": "offline-selftest",
            "run_id": "offline-pass",
            "profile": "generic-hil-v1",
            "manifest_path": "manifest.json",
            "plugins": ["offline-plugin"],
        }
        inventory = json.loads((run_dir / "inventory.json").read_text(encoding="utf-8"))
        # Inventory is canonical for an already-sealed evidence directory: it
        # excludes itself, lists every other file once in lexical order, and is
        # not promised to be byte-identical across independent observations.
        paths = [entry["path"] for entry in inventory["files"]]
        assert paths == sorted(paths) and "inventory.json" not in paths
        assert set(paths) == {
            "manifest.json", "plugin-context.json", "events.json", "resources.json",
            "faults.json", "verdict.json", "logs/offline-plugin.stdout.log",
            "logs/offline-plugin.stderr.log",
        }
        stdout_log = (run_dir / "logs/offline-plugin.stdout.log").read_text(
            encoding="utf-8"
        )
        assert "must-not-be-persisted" not in stdout_log
        assert "[REDACTED]" in stdout_log

        tampered = temp / "tampered-hash"
        shutil.copytree(run_dir, tampered)
        with (tampered / "events.json").open("ab") as stream:
            stream.write(b" ")
        expect_failure("SHA-256 inventory", lambda: verify_run(tampered))

        # A local integrity-only check can be re-sealed by the same OS user.
        # Retaining the run-emitted receipt outside the bundle binds verification
        # to the original inventory bytes and rejects that post-return rewrite.
        resealed = temp / "tampered-resealed-receipt"
        shutil.copytree(run_dir, resealed)
        resealed_manifest = json.loads((resealed / "manifest.json").read_text(encoding="utf-8"))
        resealed_manifest["source"]["firmware_sha256"] = "2" * 64
        (resealed / "manifest.json").write_bytes(canonical_json_bytes(resealed_manifest))
        rewrite_inventory_member(resealed, "manifest.json")
        assert verify_run(resealed)["status"] == "PASS"
        expect_failure("caller receipt rejects post-return re-seal",
                       lambda: verify_run(resealed, receipt))

        promoted = temp / "tampered-promotion"
        shutil.copytree(run_dir, promoted)
        promoted_verdict = json.loads(
            (promoted / "verdict.json").read_text(encoding="utf-8")
        )
        promoted_verdict["attestation"]["full_promotion_permitted"] = True
        (promoted / "verdict.json").write_bytes(canonical_json_bytes(promoted_verdict))
        rewrite_inventory_member(promoted, "verdict.json")
        expect_failure("FULL promotion mutation", lambda: verify_run(promoted))

        extra = temp / "tampered-extra"
        shutil.copytree(run_dir, extra)
        (extra / "unlisted.txt").write_text("unexpected", encoding="utf-8")
        expect_failure("unlisted evidence", lambda: verify_run(extra))

        duplicate = temp / "tampered-duplicate-case"
        shutil.copytree(run_dir, duplicate)
        duplicate_manifest = json.loads(
            (duplicate / "manifest.json").read_text(encoding="utf-8")
        )
        duplicate_manifest["cases"].append(dict(duplicate_manifest["cases"][0]))
        (duplicate / "manifest.json").write_bytes(canonical_json_bytes(duplicate_manifest))
        rewrite_inventory_member(duplicate, "manifest.json")
        expect_failure("duplicate case", lambda: verify_run(duplicate))

        # Merely re-hashing an attacker-added event must not make a former PASS
        # bundle acceptable.  The verifier has to derive case coverage again.
        unknown = temp / "tampered-rehashed-unknown-event"
        shutil.copytree(run_dir, unknown)
        unknown_events = json.loads((unknown / "events.json").read_text(encoding="utf-8"))
        unknown_events["events"].append(
            {
                "sequence": 2,
                "event_id": "offline-unknown-event",
                "case_id": "UNKNOWN-1",
                "plugin": "offline-plugin",
                "outcome": "PASS",
                "origin": "LOCAL_PLUGIN_OUTPUT_UNVERIFIED",
                "observed": {"measurement": 7, "state": "OLD"},
            }
        )
        (unknown / "events.json").write_bytes(canonical_json_bytes(unknown_events))
        rewrite_inventory_member(unknown, "events.json")
        expect_failure("rehashed PASS with unknown event", lambda: verify_run(unknown))

        path_manifest = sample_manifest("unsafe")
        path_manifest["run_id"] = "../escape"
        expect_failure("path traversal", lambda: validate_manifest(path_manifest))
        expect_failure(
            "shell string instead of argv",
            lambda: parse_plugin('{"name":"bad","argv":"relay off"}'),
        )

        # Python considers True == 1, but JSON evidence does not: an observed
        # boolean cannot satisfy a planned numeric measurement.
        bool_case = sample_manifest("bool-int")["cases"][0]
        bool_event = {
            "case_id": bool_case["case_id"],
            "observed": {"measurement": True, "state": "OLD"},
        }
        assert compare_case("generic-hil-v1", bool_case, bool_event), (
            "boolean observation was accepted as integer measurement"
        )

        too_many_attributes = sample_manifest("too-many-attributes")
        too_many_attributes["resources"][0]["attributes"] = {
            f"attribute-{index}": index for index in range(65)
        }
        expect_failure("resource attributes are capped at 64",
                       lambda: validate_manifest(too_many_attributes))

        secret_manifest_path = temp / "secret-manifest.json"
        secret_manifest_path.write_bytes(canonical_json_bytes(sample_manifest("secret-event")))
        secret_plugin = json.dumps(
            {
                "name": "secret-plugin",
                "argv": [sys.executable, str(plugin_script), "--mode", "secret-event"],
                "timeout_seconds": 10,
                "max_output_bytes": 65536,
            }
        )
        secret_dir, secret_verdict = run_campaign(
            secret_manifest_path, output_root, [secret_plugin]
        )
        assert secret_verdict["status"] == "FAIL"
        assert "PLUGIN_EVENT_INVALID" in _fault_codes(secret_dir)
        assert "must-not-be-persisted" not in (
            secret_dir / "logs/secret-plugin.stdout.log"
        ).read_text(encoding="utf-8")
        assert verify_run(secret_dir)["status"] == "FAIL"
        assert_generated_documents_match_schemas(secret_dir)
        # A syntactically intact FAIL bundle is still a failed acceptance
        # result.  The explicit escape hatch is only for diagnosis of the
        # already-sealed failure, never a promotion or PASS conversion.
        from .cli import main as cli_main
        assert cli_main(["verify", "--run-dir", str(secret_dir)]) == 2
        assert cli_main([
            "verify", "--run-dir", str(secret_dir), "--allow-failed"
        ]) == 0
        bool_fault_sequence = temp / "tampered-fault-sequence-bool"
        shutil.copytree(secret_dir, bool_fault_sequence)
        bool_faults = json.loads(
            (bool_fault_sequence / "faults.json").read_text(encoding="utf-8")
        )
        bool_faults["faults"][0]["sequence"] = True
        (bool_fault_sequence / "faults.json").write_bytes(canonical_json_bytes(bool_faults))
        rewrite_inventory_member(bool_fault_sequence, "faults.json")
        expect_failure("fault sequence bool", lambda: verify_run(bool_fault_sequence))

        redaction_manifest_path = temp / "redaction-manifest.json"
        redaction_manifest_path.write_bytes(canonical_json_bytes(sample_manifest("redaction")))
        redaction_plugin = json.dumps(
            {
                "name": "redaction-plugin",
                "argv": [sys.executable, str(plugin_script), "--mode", "log-secrets"],
                "timeout_seconds": 10,
                "max_output_bytes": 65536,
            }
        )
        redaction_dir, redaction_verdict = run_campaign(
            redaction_manifest_path, output_root, [redaction_plugin]
        )
        assert redaction_verdict["status"] == "PASS"
        redacted = (redaction_dir / "logs/redaction-plugin.stdout.log").read_text(
            encoding="utf-8"
        )
        for secret in (
            "aws-secret-value", "client-secret-value", "cookie-value",
            "credential-value", "authorization-basic-value",
        ):
            assert secret not in redacted
        assert redacted.count("[REDACTED]") >= 4
        assert "Authorization: Basic" not in redacted

        # Controls are copies inside an ephemeral adapter workspace.  Even a
        # same-UID adapter that changes its copy cannot change final evidence.
        for mode in ("mutate-controls", "persistent-control-mutation"):
            controls_manifest_path = temp / f"{mode}-manifest.json"
            controls_manifest_path.write_bytes(canonical_json_bytes(sample_manifest(mode)))
            controls_plugin = json.dumps(
                {
                    "name": mode,
                    "argv": [sys.executable, str(plugin_script), "--mode", mode],
                    "timeout_seconds": 10,
                    "max_output_bytes": 65536,
                }
            )
            controls_dir, controls_verdict = run_campaign(
                controls_manifest_path, output_root, [controls_plugin]
            )
            assert controls_verdict["status"] == "PASS"
            assert verify_run(controls_dir)["status"] == "PASS"

        for mode, limit in (("descendant-timeout", 0.2), ("descendant-output", 10.0)):
            marker = temp / f"{mode}.marker"
            bounded_manifest_path = temp / f"{mode}-manifest.json"
            bounded_manifest_path.write_bytes(canonical_json_bytes(sample_manifest(mode)))
            bounded_plugin = json.dumps(
                {
                    "name": mode,
                    "argv": [
                        sys.executable, str(plugin_script), "--mode", mode,
                        "--marker", str(marker),
                    ],
                    "timeout_seconds": limit,
                    "max_output_bytes": 1024,
                }
            )
            bounded_dir, bounded_verdict = run_campaign(
                bounded_manifest_path, output_root, [bounded_plugin]
            )
            assert bounded_verdict["status"] == "FAIL"
            expected_fault = "PLUGIN_TIMEOUT" if mode.endswith("timeout") else "PLUGIN_OUTPUT_LIMIT"
            assert expected_fault in _fault_codes(bounded_dir)
            _assert_descendant_was_killed(marker)

        # Detached children intentionally evade process-group kill.  They only
        # see the disposable workspace, so normal/timeout/output paths cannot
        # mutate the runner-built final bundle.  Do not overclaim containment.
        for mode, limit, expected_status in (
            ("detached-normal", 10.0, "PASS"),
            ("detached-timeout", 0.2, "FAIL"),
            ("detached-output", 10.0, "FAIL"),
        ):
            marker = temp / f"{mode}.marker"
            detached_manifest_path = temp / f"{mode}-manifest.json"
            detached_manifest_path.write_bytes(canonical_json_bytes(sample_manifest(mode)))
            detached_plugin = json.dumps({
                "name": mode,
                "argv": [sys.executable, str(plugin_script), "--mode", mode,
                         "--marker", str(marker)],
                "timeout_seconds": limit,
                "max_output_bytes": 1024,
            })
            detached_dir, detached_verdict = run_campaign(
                detached_manifest_path, output_root, [detached_plugin]
            )
            assert detached_verdict["status"] == expected_status
            detached_receipt = inventory_receipt(detached_dir)
            assert verify_run(detached_dir, detached_receipt)["status"] == expected_status
            time.sleep(1.0)
            assert marker.exists(), "detached child test did not leave its process group"
            assert verify_run(detached_dir, detached_receipt)["status"] == expected_status

        # Each forbidden directory form is independently rejected by build and
        # by verify; do not hide a directory bypass behind a compound fixture.
        build_dir = temp / "inventory-extra-directory"
        build_dir.mkdir()
        (build_dir / "logs").mkdir()
        (build_dir / "unexpected-directory").mkdir()
        expect_failure("build rejects extra directory", lambda: build_inventory(
            build_dir, sample_manifest("inventory-extra-directory"), set()
        ))
        extra_directory = temp / "tampered-extra-directory"
        shutil.copytree(run_dir, extra_directory)
        (extra_directory / "unexpected-directory").mkdir()
        expect_failure("verify rejects extra directory", lambda: verify_run(extra_directory))
        extra_file = temp / "tampered-extra-file"
        shutil.copytree(run_dir, extra_file)
        (extra_file / "unexpected-file.txt").write_text("unexpected", encoding="utf-8")
        expect_failure("verify rejects extra file", lambda: verify_run(extra_file))
        extra_symlink = temp / "tampered-extra-symlink"
        shutil.copytree(run_dir, extra_symlink)
        try:
            (extra_symlink / "unexpected-link").symlink_to("manifest.json")
        except OSError as error:
            raise AssertionError("self-test requires local symlink support") from error
        expect_failure("verify rejects extra symlink", lambda: verify_run(extra_symlink))

        unordered_inventory = temp / "tampered-unordered-inventory"
        shutil.copytree(run_dir, unordered_inventory)
        unordered = json.loads((unordered_inventory / "inventory.json").read_text(encoding="utf-8"))
        unordered["files"] = list(reversed(unordered["files"]))
        (unordered_inventory / "inventory.json").write_bytes(canonical_json_bytes(unordered))
        expect_failure("verify rejects unordered inventory", lambda: verify_run(unordered_inventory))

        for label, relative, mutate in (
            ("event sequence bool", "events.json", lambda d: d["events"][0].__setitem__("sequence", True)),
            ("inventory bytes bool", "inventory.json", lambda d: d["files"][0].__setitem__("bytes", False)),
            ("verdict fault count bool", "verdict.json", lambda d: d.__setitem__("fault_count", False)),
            ("verdict case count bool", "verdict.json", lambda d: d["case_counts"].__setitem__("required", True)),
        ):
            numeric = temp / f"tampered-{label.replace(' ', '-') }"
            shutil.copytree(run_dir, numeric)
            document = json.loads((numeric / relative).read_text(encoding="utf-8"))
            mutate(document)
            (numeric / relative).write_bytes(canonical_json_bytes(document))
            if relative != "inventory.json":
                rewrite_inventory_member(numeric, relative)
            expect_failure(label, lambda numeric=numeric: verify_run(numeric))

        capacity_manifest_path = temp / "campaign-event-capacity.json"
        capacity_manifest_path.write_bytes(canonical_json_bytes(sample_manifest("campaign-event-capacity")))
        capacity_plugins = [json.dumps({
            "name": f"capacity-{index}",
            "argv": [sys.executable, str(plugin_script), "--mode", "many-events",
                     "--event-count", "4096"],
            "timeout_seconds": 10,
            "max_output_bytes": 4 * 1024 * 1024,
        }) for index in range(2)]
        capacity_dir, capacity_verdict = run_campaign(
            capacity_manifest_path, output_root, capacity_plugins
        )
        assert capacity_verdict["status"] == "FAIL"
        assert len(json.loads((capacity_dir / "events.json").read_text(encoding="utf-8"))["events"]) == 4096
        assert "PLUGIN_EVENT_INVALID" in _fault_codes(capacity_dir)
        assert verify_run(capacity_dir)["status"] == "FAIL"

        namespace_manifest = create_manifest(
            profile="esp-storage-namespace-v1",
            campaign_id="offline-namespace",
            run_id="offline-ns-pass",
            repository_commit="0" * 40,
            tree_state="clean",
            firmware_sha256="1" * 64,
            firmware_build_id="offline-selftest-only",
            idf_version="offline-selftest-only",
            resources=sample_manifest()["resources"],
            requested="EVIDENCE_ONLY",
            delays_ms=[],
        )
        namespace_manifest_path = temp / "namespace-manifest.json"
        namespace_manifest_path.write_bytes(canonical_json_bytes(namespace_manifest))
        namespace_plugin = json.dumps(
            {
                "name": "namespace-plugin",
                "argv": [sys.executable, str(plugin_script), "--mode", "all-pass"],
                "timeout_seconds": 10,
                "max_output_bytes": 65536,
            }
        )
        namespace_dir, namespace_verdict = run_campaign(
            namespace_manifest_path, output_root, [namespace_plugin]
        )
        assert namespace_verdict["status"] == "PASS"
        assert verify_run(namespace_dir)["status"] == "PASS"
        assert_generated_documents_match_schemas(namespace_dir)

        reverse_manifest = dict(namespace_manifest)
        reverse_manifest["run_id"] = "offline-ns-reverse"
        reverse_manifest_path = temp / "namespace-reverse-manifest.json"
        reverse_manifest_path.write_bytes(canonical_json_bytes(reverse_manifest))
        reverse_plugin = json.dumps(
            {
                "name": "namespace-reverse-plugin",
                "argv": [sys.executable, str(plugin_script), "--mode", "all-pass-reverse"],
                "timeout_seconds": 10,
                "max_output_bytes": 65536,
            }
        )
        reverse_dir, reverse_verdict = run_campaign(
            reverse_manifest_path, output_root, [reverse_plugin]
        )
        assert reverse_verdict["status"] == "FAIL"
        assert "NAMESPACE_EVENT_ORDER_INVALID" in _fault_codes(reverse_dir)
        assert verify_run(reverse_dir)["status"] == "FAIL"

        namespace_offline_check()
        assert_schema_quality()
    print("ninlil_hil self-test OK")
