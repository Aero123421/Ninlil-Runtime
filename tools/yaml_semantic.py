#!/usr/bin/env python3
"""YAML 1.1 semantic load for release authority gates.

Uses vendored PyYAML (tools/_vendor) so Unicode escapes, anchors, aliases,
merge keys, and duplicate-key resolution match GitHub Actions YAML semantics.
Hand-rolled regex parsers must not be used for workflow identity.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_VENDOR = Path(__file__).resolve().parent / "_vendor"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

try:
    import yaml  # type: ignore
    from yaml.loader import SafeLoader  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "PyYAML is required for semantic workflow authority "
        f"(expected under tools/_vendor): {exc}"
    ) from exc


class UniqueKeySafeLoader(SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (fail-closed)."""


def _construct_mapping(loader: SafeLoader, node: Any, deep: bool = False) -> dict:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_yaml_document(text: str) -> Any:
    """Parse one YAML document with full escape/anchor/alias/merge resolution."""
    try:
        return yaml.load(text, Loader=UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML semantic parse failed: {exc}") from exc


def as_mapping(value: Any) -> dict[Any, Any] | None:
    return value if isinstance(value, dict) else None


def as_sequence(value: Any) -> list[Any] | None:
    return value if isinstance(value, list) else None


def walk_job_steps(workflow: Any) -> list[tuple[str, int | None, dict[Any, Any]]]:
    """Return (job_id, step_index|None, mapping) for jobs and each step.

    Job-level reusable-workflow call maps use step_index=None.
    """
    root = as_mapping(workflow)
    if root is None:
        raise ValueError("workflow root must be a mapping")
    jobs = as_mapping(root.get("jobs"))
    if jobs is None:
        raise ValueError("workflow jobs must be a mapping")
    out: list[tuple[str, int | None, dict[Any, Any]]] = []
    for job_id, job in jobs.items():
        job_map = as_mapping(job)
        if job_map is None:
            continue
        jid = str(job_id)
        # Reusable workflow job call.
        if "uses" in job_map:
            out.append((jid, None, job_map))
        steps = as_sequence(job_map.get("steps"))
        if steps is None:
            continue
        for index, step in enumerate(steps):
            step_map = as_mapping(step)
            if step_map is not None:
                out.append((jid, index, step_map))
    return out


def step_uses(step: dict[Any, Any]) -> str | None:
    if "uses" not in step:
        return None
    value = step.get("uses")
    if value is None:
        return None
    return str(value)


def step_with(step: dict[Any, Any]) -> dict[Any, Any]:
    with_map = as_mapping(step.get("with"))
    return with_map if with_map is not None else {}


def step_env(step: dict[Any, Any]) -> dict[Any, Any]:
    env_map = as_mapping(step.get("env"))
    return env_map if env_map is not None else {}


def step_run(step: dict[Any, Any]) -> str | None:
    if "run" not in step:
        return None
    value = step.get("run")
    if value is None:
        return None
    return str(value)
