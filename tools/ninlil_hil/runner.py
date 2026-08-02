"""Bounded plugin execution and tamper-evident evidence directory handling."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .model import (
    EVENTS_SCHEMA,
    EVENT_PREFIX,
    FAULTS_SCHEMA,
    INVENTORY_SCHEMA,
    ORIGIN,
    RESOURCES_SCHEMA,
    VERDICT_SCHEMA,
    EvidenceError,
    canonical_json_bytes,
    compare_case,
    load_json_file,
    redact_text,
    require,
    require_exact_keys,
    require_id,
    require_exact_int,
    validate_json_value,
    validate_manifest,
    validate_namespace_campaign,
    validate_plugin_event,
)


DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_TIMEOUT_SECONDS = 48.0 * 60.0 * 60.0
DEFAULT_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_PLUGINS = 32
MAX_CAMPAIGN_TIMEOUT_SECONDS = 7.0 * 24.0 * 60.0 * 60.0
MAX_CAMPAIGN_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 4096
MAX_FAULTS = 4096
LOG_DIR = "logs"
CORE_FILES = (
    "manifest.json",
    "plugin-context.json",
    "events.json",
    "resources.json",
    "faults.json",
    "verdict.json",
)
MAX_INVENTORY_FILES = len(CORE_FILES) + (2 * MAX_PLUGINS)


def safe_write(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def parse_plugin(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"plugin JSON is invalid: {error}") from error
    plugin = require_exact_keys(
        value, {"name", "argv"}, {"timeout_seconds", "max_output_bytes"}, "plugin"
    )
    name = require_id(plugin["name"], "plugin name")
    argv = plugin["argv"]
    require(isinstance(argv, list) and 1 <= len(argv) <= 128,
            f"plugin {name} argv must be a non-empty JSON array")
    for index, item in enumerate(argv):
        require(
            isinstance(item, str)
            and 0 < len(item) <= 4096
            and "\x00" not in item
            and "\n" not in item
            and "\r" not in item,
            f"plugin {name} argv[{index}] is invalid",
        )
    timeout = plugin.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    require(
        isinstance(timeout, (int, float))
        and not isinstance(timeout, bool)
        and 0.1 <= float(timeout) <= MAX_TIMEOUT_SECONDS,
        f"plugin {name} timeout_seconds is out of range",
    )
    maximum = plugin.get("max_output_bytes", DEFAULT_OUTPUT_BYTES)
    require(
        isinstance(maximum, int)
        and not isinstance(maximum, bool)
        and 1024 <= maximum <= MAX_OUTPUT_BYTES,
        f"plugin {name} max_output_bytes is out of range",
    )
    return {
        "name": name,
        "argv": argv,
        "timeout_seconds": float(timeout),
        "max_output_bytes": maximum,
    }


def plugin_environment(context_path: Path, plugin_name: str) -> dict[str, str]:
    allowed = ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
    env = {name: os.environ[name] for name in allowed if name in os.environ}
    env["NINLIL_HIL_CONTEXT"] = str(context_path)
    env["NINLIL_HIL_PLUGIN"] = plugin_name
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_bounded_plugin(
    plugin: dict[str, Any], context_path: Path
) -> tuple[int | None, bytes, bytes, str | None]:
    """Run argv without a shell and cap combined stdout/stderr in memory."""
    process = subprocess.Popen(
        plugin["argv"],
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=plugin_environment(context_path, plugin["name"]),
        close_fds=True,
        start_new_session=(os.name == "posix"),
        cwd=context_path.parent,
    )
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    lock = threading.Lock()
    exceeded = threading.Event()
    maximum = plugin["max_output_bytes"]

    def kill_process_tree() -> None:
        """Best-effort kill of the plugin's original private process group."""
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass

    def drain(label: str, stream: Any) -> None:
        try:
            # BufferedReader.read(n) may wait for n bytes or EOF, allowing a
            # child which inherited the pipe to outlive an already-exceeded
            # output budget.  read1 returns currently available pipe data.
            reader = getattr(stream, "read1", stream.read)
            while True:
                chunk = reader(8192)
                if not chunk:
                    return
                with lock:
                    total = len(outputs["stdout"]) + len(outputs["stderr"])
                    remaining = maximum - total
                    if remaining > 0:
                        outputs[label].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        exceeded.set()
                        kill_process_tree()
                        return
        finally:
            stream.close()

    require(process.stdout is not None and process.stderr is not None,
            "failed to create plugin pipes")
    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    failure: str | None = None
    try:
        returncode = process.wait(timeout=plugin["timeout_seconds"])
    except subprocess.TimeoutExpired:
        failure = "PLUGIN_TIMEOUT"
        kill_process_tree()
        returncode = process.wait(timeout=10.0)
    # A plugin is a bounded one-shot observation.  This best-effort process
    # group kill is not a same-UID hostile-process containment guarantee.
    kill_process_tree()
    for thread in threads:
        thread.join(timeout=10.0)
    if any(thread.is_alive() for thread in threads):
        kill_process_tree()
        failure = failure or "PLUGIN_PIPE_DRAIN_TIMEOUT"
    if exceeded.is_set():
        failure = "PLUGIN_OUTPUT_LIMIT"
    return returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]), failure


def extract_events(stdout: bytes, maximum: int = MAX_EVENTS) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    decoded = stdout.decode("utf-8", errors="replace")
    for line_number, line in enumerate(decoded.splitlines(), 1):
        if not line.startswith(EVENT_PREFIX):
            continue
        payload = line[len(EVENT_PREFIX):]
        try:
            value = json.loads(payload)
            if len(events) >= maximum:
                errors.append(f"line {line_number}: campaign event capacity exceeded")
                break
            events.append(validate_plugin_event(value))
        except (json.JSONDecodeError, EvidenceError) as error:
            errors.append(f"line {line_number}: {error}")
    return events, errors


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(128 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_inventory(
    run_dir: Path,
    manifest: dict[str, Any],
    allowed_paths: set[str] | None = None,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if path.name == "inventory.json":
            continue
        require(not path.is_symlink(), f"evidence contains symlink: {path}")
        if path.is_dir():
            require(path.relative_to(run_dir).as_posix() == LOG_DIR,
                    f"evidence contains an unplanned directory: {path}")
            continue
        require(path.is_file() and not path.is_symlink(),
                f"evidence contains non-regular path: {path}")
        relative = path.relative_to(run_dir).as_posix()
        require(not relative.startswith(".") and ".." not in relative.split("/"),
                f"unsafe inventory path: {relative}")
        files.append(
            {"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    if allowed_paths is not None:
        require(
            {entry["path"] for entry in files} == allowed_paths,
            "plugin created a missing or unplanned evidence path",
        )
    return {
        "schema": INVENTORY_SCHEMA,
        "campaign_id": manifest["campaign_id"],
        "run_id": manifest["run_id"],
        "files": files,
    }


def inventory_receipt(run_dir: Path) -> str:
    """Return the externally retainable SHA-256 receipt for inventory bytes."""
    return sha256_file(run_dir / "inventory.json")


def _create_plugin_workspace(
    campaign_dir: Path, manifest: dict[str, Any], names: list[str], plugin_name: str,
    manifest_bytes: bytes,
) -> tuple[Path, Path]:
    """Make one ephemeral, isolated control-copy workspace for a plugin.

    This is a containment boundary for operator-trusted local fixture adapters,
    not a portable hostile-same-UID sandbox.  No final evidence path is present
    in this workspace or its context.
    """
    workspace = campaign_dir / f".{manifest['run_id']}.plugin-{plugin_name}-{os.getpid()}"
    require(not workspace.exists(), f"plugin workspace already exists: {workspace}")
    workspace.mkdir(mode=0o700)
    context = {
        "schema": "ninlil-hil-plugin-context-v1",
        "campaign_id": manifest["campaign_id"],
        "run_id": manifest["run_id"],
        "profile": manifest["profile"],
        "manifest_path": "manifest.json",
        "plugins": names,
    }
    context_path = workspace / "plugin-context.json"
    safe_write(workspace / "manifest.json", manifest_bytes)
    safe_write(context_path, canonical_json_bytes(context))
    # These permissions prevent accidental writes by normal adapters.  They do
    # not claim to contain malicious code running as the same OS identity.
    try:
        os.chmod(workspace / "manifest.json", 0o400)
        os.chmod(context_path, 0o400)
        os.chmod(workspace, 0o500)
    except OSError:
        pass
    return workspace, context_path


def run_campaign(
    manifest_path: Path, output_root: Path, plugin_values: list[str]
) -> tuple[Path, dict[str, Any]]:
    manifest = validate_manifest(load_json_file(manifest_path))
    plugins = [parse_plugin(raw) for raw in plugin_values]
    require(plugins, "at least one --plugin-json is required")
    require(len(plugins) <= MAX_PLUGINS, "plugin count exceeds campaign capacity")
    require(
        sum(plugin["timeout_seconds"] for plugin in plugins)
        <= MAX_CAMPAIGN_TIMEOUT_SECONDS,
        "aggregate plugin timeout exceeds campaign capacity",
    )
    require(
        sum(plugin["max_output_bytes"] for plugin in plugins)
        <= MAX_CAMPAIGN_OUTPUT_BYTES,
        "aggregate plugin output exceeds campaign capacity",
    )
    names = [plugin["name"] for plugin in plugins]
    require(len(set(names)) == len(names), "plugin names must be unique")

    root = output_root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    campaign_dir = root / manifest["campaign_id"]
    campaign_dir.mkdir(mode=0o700, exist_ok=True)
    require(campaign_dir.is_dir() and not campaign_dir.is_symlink(),
            f"campaign path is not a real directory: {campaign_dir}")
    final_dir = campaign_dir / manifest["run_id"]
    require(not final_dir.exists(), f"run directory already exists: {final_dir}")
    temp_dir = campaign_dir / f".{manifest['run_id']}.partial-{os.getpid()}"
    require(not temp_dir.exists(), f"partial run directory already exists: {temp_dir}")

    events: list[dict[str, Any]] = []
    faults: list[dict[str, Any]] = []
    captured_logs: dict[str, tuple[bytes, bytes]] = {}
    staging_created = False
    try:
        manifest_bytes = canonical_json_bytes(manifest)
        context = {
            "schema": "ninlil-hil-plugin-context-v1",
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "profile": manifest["profile"],
            "manifest_path": "manifest.json",
            "plugins": names,
        }
        context_bytes = canonical_json_bytes(context)

        def add_fault(
            code: str, message: str, plugin: str | None = None,
            case_id: str | None = None, severity: str = "ERROR"
        ) -> None:
            if len(faults) >= MAX_FAULTS:
                if faults[-1]["code"] != "FAULT_CAPACITY_EXCEEDED":
                    faults[-1] = {
                        "sequence": MAX_FAULTS,
                        "code": "FAULT_CAPACITY_EXCEEDED",
                        "severity": "ERROR",
                        "plugin": None,
                        "case_id": None,
                        "message": "fault capacity exceeded",
                    }
                return
            faults.append(
                {
                    "sequence": len(faults) + 1,
                    "code": code,
                    "severity": severity,
                    "plugin": plugin,
                    "case_id": case_id,
                    "message": redact_text(message)[:1024],
                }
            )

        emitted_event_ids: set[str] = set()
        for plugin in plugins:
            name = plugin["name"]
            workspace: Path | None = None
            try:
                workspace, context_path = _create_plugin_workspace(
                    campaign_dir, manifest, names, name, manifest_bytes
                )
                returncode, stdout, stderr, execution_failure = run_bounded_plugin(
                    plugin, context_path
                )
            except OSError:
                returncode, stdout, stderr = None, b"", b""
                execution_failure = "PLUGIN_START_FAILED"
            finally:
                if workspace is not None:
                    # A detached same-UID descendant may survive best-effort
                    # process-group termination.  Removing its workspace still
                    # cannot affect runner-held bytes or final evidence.
                    try:
                        os.chmod(workspace, 0o700)
                    except OSError:
                        pass
                    shutil.rmtree(workspace, ignore_errors=True)
            redacted_stdout = redact_text(
                stdout.decode("utf-8", errors="replace")
            ).encode("utf-8")
            redacted_stderr = redact_text(
                stderr.decode("utf-8", errors="replace")
            ).encode("utf-8")
            captured_logs[name] = (redacted_stdout, redacted_stderr)
            if execution_failure is not None:
                add_fault(execution_failure, "bounded plugin execution failed", name)
            if returncode not in (0, None):
                add_fault("PLUGIN_EXIT_NONZERO", f"plugin exit code {returncode}", name)

            parsed, parse_errors = extract_events(stdout, MAX_EVENTS - len(events))
            for error in parse_errors:
                add_fault("PLUGIN_EVENT_INVALID", error, name)
            for event in parsed:
                if event["event_id"] in emitted_event_ids:
                    add_fault(
                        "DUPLICATE_EVENT_ID",
                        "plugin emitted a duplicate event_id",
                        name,
                        event["case_id"],
                    )
                    continue
                emitted_event_ids.add(event["event_id"])
                if len(events) >= MAX_EVENTS:
                    add_fault("CAMPAIGN_EVENT_CAPACITY_EXCEEDED",
                              "campaign event capacity exceeded", name)
                    break
                events.append(
                    {
                        "sequence": len(events) + 1,
                        "event_id": event["event_id"],
                        "case_id": event["case_id"],
                        "plugin": name,
                        "outcome": event["outcome"],
                        "origin": ORIGIN,
                        "observed": event["observed"],
                    }
                )

        case_map = {case["case_id"]: case for case in manifest["cases"]}
        by_case: dict[str, list[dict[str, Any]]] = {
            case_id: [] for case_id in case_map
        }
        for event in events:
            case_id = event["case_id"]
            if case_id not in by_case:
                add_fault("UNPLANNED_CASE", "plugin emitted an unplanned case",
                          event["plugin"], case_id)
            else:
                by_case[case_id].append(event)

        passed: list[str] = []
        failed: list[str] = []
        accepted_events: list[dict[str, Any]] = []
        for case_id, case in case_map.items():
            case_events = by_case[case_id]
            if len(case_events) != 1:
                add_fault(
                    "CASE_EVENT_CARDINALITY",
                    f"expected exactly one event, got {len(case_events)}",
                    case_id=case_id,
                )
                failed.append(case_id)
                continue
            event = case_events[0]
            if event["outcome"] != "PASS":
                add_fault(
                    "CASE_NOT_PASS", f"event outcome is {event['outcome']}",
                    event["plugin"], case_id
                )
                failed.append(case_id)
                continue
            comparison_errors = compare_case(manifest["profile"], case, event)
            if comparison_errors:
                for error in comparison_errors:
                    add_fault("CASE_OBSERVATION_MISMATCH", error,
                              event["plugin"], case_id)
                failed.append(case_id)
                continue
            passed.append(case_id)
            accepted_events.append(event)

        if manifest["profile"] == "esp-storage-namespace-v1":
            expected_order = [case["case_id"] for case in manifest["cases"]]
            observed_order = [
                event["case_id"] for event in events if event["case_id"] in case_map
            ]
            if observed_order != expected_order:
                add_fault(
                    "NAMESPACE_EVENT_ORDER_INVALID",
                    "namespace events are not in the required phase order",
                )
            namespace_errors = validate_namespace_campaign(accepted_events)
            if namespace_errors:
                for error in namespace_errors:
                    add_fault("NAMESPACE_CAMPAIGN_INVALID", error)
                for case_id in list(passed):
                    if case_id not in failed:
                        failed.append(case_id)
                passed.clear()

        passed.sort()
        failed = sorted(set(failed))
        evidence_complete = (
            len(passed) == len(case_map) and not failed and not faults
        )
        status = "PASS" if evidence_complete else "FAIL"
        events_document = {
            "schema": EVENTS_SCHEMA,
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "events": events,
        }
        resources_document = {
            "schema": RESOURCES_SCHEMA,
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "resources": manifest["resources"],
        }
        faults_document = {
            "schema": FAULTS_SCHEMA,
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "faults": faults,
        }
        reasons = [
            "LOCAL_PLUGIN_OUTPUT_IS_NOT_AN_ATTESTATION",
            "ACCEPTED_STORAGE_SEMANTICS_KEEP_ESP_UNPROVEN",
            "SEPARATE_ACCEPTED_PROMOTION_AUTHORITY_REQUIRED",
        ]
        if manifest["source"]["tree_state"] != "clean":
            reasons.append("SOURCE_TREE_NOT_CLEAN")
        if not evidence_complete:
            reasons.append("EVIDENCE_INCOMPLETE_OR_FAILED")
        verdict = {
            "schema": VERDICT_SCHEMA,
            "campaign_id": manifest["campaign_id"],
            "run_id": manifest["run_id"],
            "profile": manifest["profile"],
            "status": status,
            "evidence_complete": evidence_complete,
            "case_counts": {
                "required": len(case_map),
                "passed": len(passed),
                "failed": len(failed),
            },
            "passed_cases": passed,
            "failed_cases": failed,
            "fault_count": len(faults),
            "attestation": {
                "requested": manifest["attestation"]["requested"],
                "evidence_origin": ORIGIN,
                "full_promotion_permitted": False,
                "runtime_policy": "ESP_UNPROVEN",
                "physical_hil_claimed": False,
                "reason_codes": reasons,
            },
        }
        # Final evidence is constructed only after every plugin has stopped
        # (or been bounded) and only from runner-held canonical control bytes
        # and captured output.  Plugins never receive this directory's path.
        temp_dir.mkdir(mode=0o700)
        staging_created = True
        (temp_dir / LOG_DIR).mkdir(mode=0o700)
        for name in names:
            stdout_log, stderr_log = captured_logs[name]
            safe_write(temp_dir / LOG_DIR / f"{name}.stdout.log", stdout_log)
            safe_write(temp_dir / LOG_DIR / f"{name}.stderr.log", stderr_log)
        safe_write(temp_dir / "manifest.json", manifest_bytes)
        safe_write(temp_dir / "plugin-context.json", context_bytes)
        safe_write(temp_dir / "events.json", canonical_json_bytes(events_document))
        safe_write(temp_dir / "resources.json", canonical_json_bytes(resources_document))
        safe_write(temp_dir / "faults.json", canonical_json_bytes(faults_document))
        safe_write(temp_dir / "verdict.json", canonical_json_bytes(verdict))
        allowed_paths = set(CORE_FILES)
        allowed_paths.update(
            f"{LOG_DIR}/{name}.{stream}.log"
            for name in names
            for stream in ("stdout", "stderr")
        )
        inventory = build_inventory(temp_dir, manifest, allowed_paths)
        safe_write(temp_dir / "inventory.json", canonical_json_bytes(inventory))
        os.rename(temp_dir, final_dir)
        return final_dir, verdict
    except BaseException:
        if staging_created:
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def verify_run(run_dir: Path, expected_receipt: str | None = None) -> dict[str, Any]:
    require(not run_dir.is_symlink(), "run path must not be a symlink")
    run_dir = run_dir.resolve()
    require(run_dir.is_dir() and not run_dir.is_symlink(),
            "run path must be a real directory")
    if expected_receipt is not None:
        require(isinstance(expected_receipt, str)
                and len(expected_receipt) == 64
                and all(character in "0123456789abcdef" for character in expected_receipt),
                "expected receipt must be lowercase SHA-256")
        require(inventory_receipt(run_dir) == expected_receipt,
                "inventory receipt does not match the caller-supplied receipt")
    inventory = load_json_file(run_dir / "inventory.json")
    require_exact_keys(
        inventory, {"schema", "campaign_id", "run_id", "files"}, set(), "inventory"
    )
    require(inventory["schema"] == INVENTORY_SCHEMA, "unsupported inventory schema")
    files = inventory["files"]
    require(
        isinstance(files, list)
        and len(CORE_FILES) <= len(files) <= MAX_INVENTORY_FILES,
        "inventory files invalid",
    )
    listed: set[str] = set()
    prior_path: str | None = None
    for index, entry in enumerate(files):
        require_exact_keys(entry, {"path", "bytes", "sha256"}, set(),
                           f"inventory.files[{index}]")
        relative = entry["path"]
        require(
            isinstance(relative, str)
            and relative
            and not relative.startswith("/")
            and ".." not in relative.split("/")
            and relative not in listed,
            f"unsafe/duplicate inventory path {relative!r}",
        )
        require(prior_path is None or prior_path < relative,
                "inventory paths are not strict lexical order")
        prior_path = relative
        require_exact_int(entry["bytes"], f"inventory.files[{index}].bytes")
        listed.add(relative)
        path = run_dir / relative
        require(path.is_file() and not path.is_symlink(),
                f"inventory member is not a regular file: {relative}")
        require(path.stat().st_size == entry["bytes"], f"size mismatch: {relative}")
        require(sha256_file(path) == entry["sha256"],
                f"SHA-256 mismatch: {relative}")
    actual = {
        path.relative_to(run_dir).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    require(not any(path.is_symlink() for path in run_dir.rglob("*")),
            "run directory contains a symlink")
    for path in run_dir.rglob("*"):
        if path.is_dir():
            require(path.relative_to(run_dir).as_posix() == LOG_DIR,
                    "run directory contains an unplanned directory")
    require(actual == listed | {"inventory.json"},
            "run directory has missing or unlisted files")
    require(set(CORE_FILES).issubset(listed), "inventory omits a core evidence file")

    manifest = validate_manifest(load_json_file(run_dir / "manifest.json"))
    require(
        inventory["campaign_id"] == manifest["campaign_id"]
        and inventory["run_id"] == manifest["run_id"],
        "inventory identity mismatch",
    )
    plugin_context = load_json_file(run_dir / "plugin-context.json")
    require_exact_keys(
        plugin_context,
        {
            "schema", "campaign_id", "run_id", "profile", "manifest_path",
            "plugins",
        },
        set(),
        "plugin context",
    )
    require(
        plugin_context["schema"] == "ninlil-hil-plugin-context-v1"
        and plugin_context["campaign_id"] == manifest["campaign_id"]
        and plugin_context["run_id"] == manifest["run_id"]
        and plugin_context["profile"] == manifest["profile"],
        "plugin context identity mismatch",
    )
    require(
        isinstance(plugin_context["manifest_path"], str)
        and plugin_context["manifest_path"] == "manifest.json",
        "plugin context manifest path is invalid",
    )
    plugin_names = plugin_context["plugins"]
    require(
        isinstance(plugin_names, list)
        and 1 <= len(plugin_names) <= MAX_PLUGINS
        and all(require_id(name, "plugin context name") == name for name in plugin_names)
        and len(set(plugin_names)) == len(plugin_names),
        "plugin context plugins are invalid",
    )
    expected_listed = set(CORE_FILES)
    expected_listed.update(
        f"{LOG_DIR}/{name}.{stream}.log"
        for name in plugin_names
        for stream in ("stdout", "stderr")
    )
    require(listed == expected_listed, "inventory path set is not canonical")
    events = load_json_file(run_dir / "events.json")
    resources = load_json_file(run_dir / "resources.json")
    faults = load_json_file(run_dir / "faults.json")
    verdict = load_json_file(run_dir / "verdict.json")
    _verify_documents(manifest, events, resources, faults, verdict)
    return verdict


def _verify_documents(
    manifest: dict[str, Any],
    events: Any,
    resources: Any,
    faults: Any,
    verdict: Any,
) -> None:
    identity = (manifest["campaign_id"], manifest["run_id"])
    for name, document, schema, payload in (
        ("events", events, EVENTS_SCHEMA, "events"),
        ("resources", resources, RESOURCES_SCHEMA, "resources"),
        ("faults", faults, FAULTS_SCHEMA, "faults"),
    ):
        require_exact_keys(
            document, {"schema", "campaign_id", "run_id", payload}, set(), name
        )
        require(document["schema"] == schema, f"{name} schema mismatch")
        require((document["campaign_id"], document["run_id"]) == identity,
                f"{name} identity mismatch")
        require(isinstance(document[payload], list), f"{name} payload invalid")
        require(
            len(document[payload]) <= (
                MAX_EVENTS if payload == "events"
                else MAX_FAULTS if payload == "faults"
                else 64
            ),
            f"{name} payload exceeds capacity",
        )
    require(resources["resources"] == manifest["resources"],
            "resources differ from manifest declarations")

    event_ids: set[str] = set()
    manifest_case_ids = {case["case_id"] for case in manifest["cases"]}
    unknown_case_ids: set[str] = set()
    for index, event in enumerate(events["events"]):
        require_exact_keys(
            event,
            {
                "sequence", "event_id", "case_id", "plugin", "outcome",
                "origin", "observed",
            },
            set(),
            f"events[{index}]",
        )
        require_exact_int(event["sequence"], f"events[{index}].sequence", minimum=1,
                          maximum=MAX_EVENTS)
        require(event["sequence"] == index + 1, "event sequence is not canonical")
        require_id(event["event_id"], "event_id")
        require(event["event_id"] not in event_ids, "duplicate event_id")
        event_ids.add(event["event_id"])
        require_id(event["case_id"], "event case_id")
        require_id(event["plugin"], "event plugin")
        require(event["outcome"] in {"PASS", "FAIL", "ERROR"}, "invalid outcome")
        require(event["origin"] == ORIGIN, "event origin overclaims verification")
        require(isinstance(event["observed"], dict), "event observation invalid")
        validate_json_value(event["observed"], "event observed")
        if event["case_id"] not in manifest_case_ids:
            unknown_case_ids.add(event["case_id"])

    for index, fault in enumerate(faults["faults"]):
        require_exact_keys(
            fault, {"sequence", "code", "severity", "plugin", "case_id", "message"},
            set(), f"faults[{index}]"
        )
        require_exact_int(fault["sequence"], f"faults[{index}].sequence", minimum=1,
                          maximum=MAX_FAULTS)
        require(fault["sequence"] == index + 1, "fault sequence is not canonical")
        require_id(fault["code"], "fault code")
        require(fault["severity"] in {"ERROR", "WARNING"}, "invalid fault severity")
        if fault["plugin"] is not None:
            require_id(fault["plugin"], "fault plugin")
        if fault["case_id"] is not None:
            require_id(fault["case_id"], "fault case_id")
        require(isinstance(fault["message"], str) and len(fault["message"]) <= 1024,
                "fault message invalid")

    require_exact_keys(
        verdict,
        {
            "schema", "campaign_id", "run_id", "profile", "status",
            "evidence_complete", "case_counts", "passed_cases", "failed_cases",
            "fault_count", "attestation",
        },
        set(),
        "verdict",
    )
    require(verdict["schema"] == VERDICT_SCHEMA, "verdict schema mismatch")
    require((verdict["campaign_id"], verdict["run_id"]) == identity,
            "verdict identity mismatch")
    require(verdict["profile"] == manifest["profile"], "verdict profile mismatch")
    require(verdict["status"] in {"PASS", "FAIL"}, "invalid verdict status")
    require(isinstance(verdict["evidence_complete"], bool), "invalid completeness")
    counts = require_exact_keys(
        verdict["case_counts"], {"required", "passed", "failed"}, set(),
        "verdict.case_counts"
    )
    required = len(manifest["cases"])
    for key in ("required", "passed", "failed"):
        require_exact_int(counts[key], f"verdict.case_counts.{key}", minimum=0,
                          maximum=MAX_EVENTS)
    require(counts["required"] == required, "required case count mismatch")
    require(isinstance(verdict["passed_cases"], list)
            and isinstance(verdict["failed_cases"], list), "invalid case lists")
    for label in ("passed_cases", "failed_cases"):
        require(
            all(
                isinstance(case_id, str)
                and require_id(case_id, f"verdict {label} case") == case_id
                for case_id in verdict[label]
            ),
            f"invalid {label}",
        )
        require(
            verdict[label] == sorted(set(verdict[label])),
            f"{label} must be sorted and unique",
        )
    require(counts["passed"] == len(verdict["passed_cases"])
            and counts["failed"] == len(verdict["failed_cases"]),
            "case count/list mismatch")
    require_exact_int(verdict["fault_count"], "verdict.fault_count", minimum=0,
                      maximum=MAX_FAULTS)
    require(verdict["fault_count"] == len(faults["faults"]), "fault count mismatch")
    complete = (
        counts["passed"] == required
        and counts["failed"] == 0
        and verdict["fault_count"] == 0
    )
    require(verdict["evidence_complete"] == complete, "completeness is inconsistent")
    require(verdict["status"] == ("PASS" if complete else "FAIL"),
            "status is inconsistent")
    if unknown_case_ids:
        require(
            verdict["status"] == "FAIL"
            and all(
                any(
                    fault["code"] == "UNPLANNED_CASE"
                    and fault["case_id"] == case_id
                    for fault in faults["faults"]
                )
                for case_id in unknown_case_ids
            ),
            "unknown event case is not represented as a failed unplanned case",
        )
    attestation = require_exact_keys(
        verdict["attestation"],
        {
            "requested", "evidence_origin", "full_promotion_permitted",
            "runtime_policy", "physical_hil_claimed", "reason_codes",
        },
        set(),
        "verdict.attestation",
    )
    require(attestation["requested"] == manifest["attestation"]["requested"],
            "attestation request mismatch")
    require(attestation["evidence_origin"] == ORIGIN, "attestation origin overclaim")
    require(attestation["full_promotion_permitted"] is False,
            "v1 must never authorize FULL promotion")
    require(attestation["runtime_policy"] == "ESP_UNPROVEN",
            "v1 must preserve ESP_UNPROVEN")
    require(attestation["physical_hil_claimed"] is False,
            "local evidence must not claim physical HIL attested")
    reasons = attestation["reason_codes"]
    require(isinstance(reasons, list) and len(reasons) >= 1,
            "attestation reason_codes invalid")
    for reason in reasons:
        require_id(reason, "attestation reason code")
    require(len(set(reasons)) == len(reasons), "attestation reason_codes duplicate")

    case_map = {case["case_id"]: case for case in manifest["cases"]}
    by_case: dict[str, list[dict[str, Any]]] = {
        case_id: [] for case_id in case_map
    }
    derived_failed: set[str] = set()
    derived_passed: list[str] = []
    accepted_events: list[dict[str, Any]] = []
    for event in events["events"]:
        if event["case_id"] not in by_case:
            derived_failed.add(event["case_id"])
        else:
            by_case[event["case_id"]].append(event)
    for case_id, case in case_map.items():
        case_events = by_case[case_id]
        if len(case_events) != 1:
            derived_failed.add(case_id)
            continue
        event = case_events[0]
        if event["outcome"] != "PASS" or compare_case(
            manifest["profile"], case, event
        ):
            derived_failed.add(case_id)
            continue
        derived_passed.append(case_id)
        accepted_events.append(event)
    if manifest["profile"] == "esp-storage-namespace-v1":
        expected_order = [case["case_id"] for case in manifest["cases"]]
        observed_order = [
            event["case_id"]
            for event in events["events"]
            if event["case_id"] in case_map
        ]
        if verdict["status"] == "PASS":
            require(
                observed_order == expected_order,
                "namespace events are not in the required phase order",
            )
        elif observed_order != expected_order:
            require(
                any(
                    fault["code"] == "NAMESPACE_EVENT_ORDER_INVALID"
                    for fault in faults["faults"]
                ),
                "namespace event order failure is missing its fault",
            )
        if validate_namespace_campaign(accepted_events):
            derived_failed.update(case_map)
            derived_passed.clear()
    derived_passed.sort()
    require(verdict["passed_cases"] == derived_passed,
            "verdict passed_cases do not match event evidence")
    require(
        set(verdict["failed_cases"]) == (derived_failed & set(case_map)),
        "verdict failed_cases do not match event evidence",
    )
