#!/usr/bin/env python3
"""Offline-only hostile test plugin for the Ninlil HIL runner.

Every mode stays local and uses only a temporary marker supplied by the
self-test.  The ordinary descendant modes remain in the runner-created group;
the detached modes deliberately escape it to prove final evidence does not
depend on hostile same-UID child containment.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def emit_case(case: dict[str, Any], index: int) -> None:
    observed = dict(case["expected"])
    for key, choices in case["allowed"].items():
        observed[key] = choices[0]
    event = {
        "event_id": f"offline-event-{index}",
        "case_id": case["case_id"],
        "outcome": "PASS",
        "observed": observed,
    }
    print("NINLIL_HIL_EVENT_V1 " + json.dumps(event, separators=(",", ":")))


def spawn_marker_child(marker: Path, *, detached: bool = False, mutate_controls: bool = False) -> None:
    mutation = ""
    if mutate_controls:
        mutation = (
            "; pathlib.Path('.').chmod(0o700)"
            "; pathlib.Path('manifest.json').chmod(0o600)"
            "; pathlib.Path('manifest.json').write_text('{\\\"adapter\\\":\\\"changed\\\"}', encoding='utf-8')"
        )
    code = (
        "import pathlib,time; "
        "time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('detached descendant', encoding='utf-8')"
        + mutation
    )
    subprocess.Popen(
        [sys.executable, "-c", code], close_fds=True,
        start_new_session=detached,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=(
            "pass", "all-pass", "all-pass-reverse", "secret-event",
            "log-secrets", "duplicate", "mutate-controls", "descendant-timeout",
            "descendant-output", "persistent-control-mutation",
            "detached-normal", "detached-timeout",
            "detached-output", "many-events",
        ),
        required=True,
    )
    parser.add_argument("--marker", type=Path)
    parser.add_argument("--event-count", type=int, default=0)
    args = parser.parse_args()
    context_path = Path(os.environ["NINLIL_HIL_CONTEXT"])
    context = json.loads(context_path.read_text(encoding="utf-8"))
    manifest_path = Path(context["manifest_path"])
    # The runner deliberately makes the context path relative and starts the
    # plugin in the private partial run directory.  Keep compatibility with
    # direct invocation only when an absolute path is supplied.
    if not manifest_path.is_absolute():
        manifest_path = Path.cwd() / manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print("diagnostic password=must-not-be-persisted")

    if args.mode == "log-secrets":
        print("AWS_SECRET_ACCESS_KEY=aws-secret-value")
        print("client_secret: client-secret-value")
        print("Cookie: cookie-value")
        print("Authorization: Basic authorization-basic-value")
        print("credential=credential-value")
        emit_case(manifest["cases"][0], 1)
        return 0
    if args.mode == "mutate-controls":
        Path(".").chmod(0o700)
        manifest_path.chmod(0o600)
        context_path.chmod(0o600)
        manifest_path.write_text('{"attacker":"changed"}', encoding="utf-8")
        context_path.write_text('{"attacker":"changed"}', encoding="utf-8")
        emit_case(manifest["cases"][0], 1)
        return 0
    if args.mode == "persistent-control-mutation":
        # The child inherits the runner's private working directory and mutates
        # control input while its parent is still alive.  This exercises a
        # persistent mutation rather than a one-shot parent write.
        code = (
            "import pathlib,time; time.sleep(0.05); "
            "pathlib.Path('manifest.json').write_text('{\\\"attacker\\\":\\\"changed\\\"}', encoding='utf-8'); "
            "pathlib.Path('plugin-context.json').write_text('{\\\"attacker\\\":\\\"changed\\\"}', encoding='utf-8')"
        )
        subprocess.Popen([sys.executable, "-c", code], close_fds=True)
        time.sleep(0.2)
        emit_case(manifest["cases"][0], 1)
        return 0
    if args.mode == "many-events":
        for index in range(args.event_count):
            event = {
                "event_id": f"capacity-event-{index}",
                "case_id": manifest["cases"][0]["case_id"],
                "outcome": "PASS",
                "observed": {**manifest["cases"][0]["expected"], **{
                    key: choices[0]
                    for key, choices in manifest["cases"][0]["allowed"].items()
                }},
            }
            print("NINLIL_HIL_EVENT_V1 " + json.dumps(event, separators=(",", ":")))
        return 0
    if args.mode in {"descendant-timeout", "descendant-output", "detached-timeout", "detached-output", "detached-normal"}:
        if args.marker is None:
            parser.error(f"--marker is required for {args.mode}")
        detached = args.mode.startswith("detached-")
        spawn_marker_child(args.marker, detached=detached, mutate_controls=detached)
        if args.mode.endswith("output"):
            print("X" * 4096)
            time.sleep(2.0)
        elif args.mode.endswith("timeout"):
            time.sleep(2.0)
        else:
            emit_case(manifest["cases"][0], 1)
        return 0

    selected_cases = manifest["cases"] if args.mode.startswith("all-pass") else manifest["cases"][:1]
    if args.mode == "all-pass-reverse":
        selected_cases = list(reversed(selected_cases))
    event: dict[str, Any] | None = None
    for index, case in enumerate(selected_cases, 1):
        observed = dict(case["expected"])
        for key, choices in case["allowed"].items():
            observed[key] = choices[0]
        if args.mode == "secret-event":
            observed["access_token"] = "must-not-be-persisted"
        event = {
            "event_id": f"offline-event-{index}",
            "case_id": case["case_id"],
            "outcome": "PASS",
            "observed": observed,
        }
        print("NINLIL_HIL_EVENT_V1 " + json.dumps(event, separators=(",", ":")))
    if args.mode == "duplicate":
        assert event is not None
        duplicate = dict(event)
        duplicate["event_id"] = "offline-event-2"
        print("NINLIL_HIL_EVENT_V1 " + json.dumps(duplicate, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
