#!/usr/bin/env python3
"""Independent PA-S0 canonical expected-document authority.

Architecture (docs/35 + ADR 0023 + docs/30 R6):
  * The generator/composition modules are never imported here.
  * A separately reviewed canonical byte digest freezes the candidate vector.
    Generator freshness is a different gate, so a generator defect and a
    fixture edit fail at different authorities.
  * docs/30 N6 and PA state machines are recomputed by independent modules;
    the frozen tree is only the mutation-campaign baseline.
  * Generator CLI is emission-only; gates recompute digests/fields independently.

Descriptive prose is the only allowlisted free surface:
  $.rfc9529_method3_suite2_reference.reason
  $.credentials.note
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

# --- Descriptive free-text allowlist (explicit; everything else is machine) ---

DESCRIPTIVE_ALLOWLIST_PATHS: frozenset[str] = frozenset(
    {
        "$.rfc9529_method3_suite2_reference.reason",
        "$.credentials.note",
    }
)

DESCRIPTIVE_ALLOWLIST_TOKENS: frozenset[str] = frozenset({"reason", "note"})


class ExpectedModelError(RuntimeError):
    """Canonical expected-model mismatch or campaign failure."""


_EXPECTED_CACHE: dict[str, Any] | None = None
_EXPECTED_VECTOR = (
    Path(__file__).resolve().parents[1]
    / "spec/vectors/production-attachment-edhoc-v1.json"
)
# Updated only after generator output and independent semantics are reviewed.
# This pin deliberately lives outside the composition/generator modules.
EXPECTED_VECTOR_SHA256 = (
    "95639924765712d34d5667ab48efe32aeb2d2d5cb6e7af27180d3c8480184fac"
)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ExpectedModelError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _dual_sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _dual_opaque(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def _dual_node_id16(stable: bytes) -> bytes:
    """docs/30 §994–996 (independent of r6_oracle / vector_gen)."""
    return _dual_sha256(b"NINLIL-R6-NODE-ID-v1" + _dual_opaque(stable))[:16]


def _dual_ns_fp12(
    receiver: bytes, layer: int, membership_epoch: int, alloc_side: int
) -> bytes:
    return _dual_sha256(
        receiver
        + bytes([layer & 0xFF])
        + int(membership_epoch).to_bytes(8, "big")
        + bytes([alloc_side & 0xFF])
    )[:12]


def _dual_hop_binding(fields: dict[str, Any], context_id: int, direction: int) -> bytes:
    pre = (
        b"NINLIL-R6-HOP-CTX-v1"
        + bytes([0x11, 2])
        + _dual_opaque(fields["site_domain"])
        + int(fields["membership_epoch"]).to_bytes(8, "big")
        + _dual_opaque(fields["attachment_id"])
        + int(fields["attachment_epoch"]).to_bytes(8, "big")
        + _dual_opaque(fields["initiator_stable_digest"])
        + _dual_opaque(fields["responder_stable_digest"])
        + _dual_opaque(fields["authority_id"])
        + int(fields["authority_term"]).to_bytes(8, "big")
        + int(context_id).to_bytes(4, "big")
        + bytes([direction & 0xFF])
        + (0x0003).to_bytes(2, "big")
    )
    return _dual_sha256(pre)


def _dual_e2e_binding(fields: dict[str, Any], context_id: int, direction: int) -> bytes:
    if direction == 0:
        sender = fields["initiator_stable_digest"]
        receiver = fields["responder_stable_digest"]
    else:
        sender = fields["responder_stable_digest"]
        receiver = fields["initiator_stable_digest"]
    pre = (
        b"NINLIL-R6-E2E-CTX-v1"
        + bytes([0x11, 2])
        + _dual_opaque(fields["site_domain"])
        + int(fields["membership_epoch"]).to_bytes(8, "big")
        + _dual_opaque(fields["e2e_security_id"])
        + int(fields["e2e_security_epoch"]).to_bytes(8, "big")
        + _dual_opaque(sender)
        + _dual_opaque(receiver)
        + _dual_opaque(fields["authority_id"])
        + int(fields["authority_term"]).to_bytes(8, "big")
        + int(context_id).to_bytes(4, "big")
        + bytes([direction & 0xFF])
    )
    # E2E must not bind attachment.
    if fields["attachment_id"] in pre:
        raise ExpectedModelError("dual e2e preimage contains attachment_id")
    return _dual_sha256(pre)


def _hx(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise ExpectedModelError(f"hex field type {type(value)}")


def _fields_from_install(iff: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in iff.items():
        if isinstance(v, str) and len(v) >= 2 and all(
            c in "0123456789abcdefABCDEF" for c in v
        ) and len(v) % 2 == 0:
            # hex digests / ids
            if k.endswith(
                (
                    "_digest",
                    "_id",
                    "domain",
                    "epoch",
                )
            ) or k in (
                "attachment_id",
                "site_domain",
                "authority_id",
                "e2e_security_id",
                "lease_clock_epoch",
                "initiator_stable_digest",
                "responder_stable_digest",
            ):
                try:
                    out[k] = bytes.fromhex(v)
                    continue
                except ValueError:
                    pass
        out[k] = v
    # ensure ints
    for k in (
        "membership_epoch",
        "attachment_epoch",
        "authority_term",
        "e2e_security_epoch",
        "lease_epoch",
    ):
        if k in out and not isinstance(out[k], int):
            out[k] = int(out[k])
    return out


def assert_role_images_match_docs30_dual(document: dict[str, Any]) -> None:
    """Independent dual recompute of role NEW 15-key + OLD 8-key images.

    Catches invented PA node/binding formulas, E2E↔attachment binding,
    wrong TX/RX counters, N6AL floor=kgen, and reattach OLD presenting lanes.
    """
    raw = document["attachment_install"]["install_fields"]
    iff = {
        "attachment_id": _hx(raw["attachment_id"]),
        "initiator_stable_digest": _hx(raw["initiator_stable_digest"]),
        "responder_stable_digest": _hx(raw["responder_stable_digest"]),
        "site_domain": _hx(raw["site_domain"]),
        "authority_id": _hx(raw["authority_id"]),
        "e2e_security_id": _hx(raw["e2e_security_id"]),
        "membership_epoch": int(raw["membership_epoch"]),
        "attachment_epoch": int(raw["attachment_epoch"]),
        "authority_term": int(raw["authority_term"]),
        "e2e_security_epoch": int(raw["e2e_security_epoch"]),
    }

    expected_floors = {41: 42, 43: 44, 47: 48, 53: 54}

    for role_name, role in (
        ("device_local_role_1", 1),
        ("authority_local_role_2", 2),
    ):
        inv = document["atomic_batch_manifests"][role_name]["exact_inventory"]
        if len(inv) != 15:
            raise ExpectedModelError(f"{role_name}: NEW inventory not 15")
        local_stable = (
            iff["initiator_stable_digest"]
            if role == 1
            else iff["responder_stable_digest"]
        )
        peer_stable = (
            iff["responder_stable_digest"]
            if role == 1
            else iff["initiator_stable_digest"]
        )
        local_node = _dual_node_id16(local_stable)
        peer_node = _dual_node_id16(peer_stable)
        lane_count = 0
        al_count = 0
        for entry in inv:
            mk = int(entry["member_kind"])
            ck = bytes.fromhex(entry["complete_key_hex"])
            val = bytes.fromhex(entry["value_hex"])
            layer = int(entry["layer_code"])
            direction = int(entry["direction"])
            lane = int(entry["lane"])
            local_side = int(entry["local_side"])
            context_id = int(entry["context_id"])
            kgen = int(entry["key_generation"])
            if mk == 1:
                lane_count += 1
                if layer == 1:
                    bind = _dual_hop_binding(iff, context_id, direction)
                else:
                    bind = _dual_e2e_binding(iff, context_id, direction)
                want = (
                    bytes([layer, lane, direction, 0])
                    + context_id.to_bytes(4, "big")
                    + bind
                    + kgen.to_bytes(8, "big")
                )
                if ck != want:
                    raise ExpectedModelError(
                        f"{role_name} {entry['identity']}: complete key != dual docs/30"
                    )
                # TX=1 / RX=0
                counter = int.from_bytes(val[8:16], "big")
                want_c = 1 if local_side == 2 else 0
                if counter != want_c:
                    raise ExpectedModelError(
                        f"{role_name} {entry['identity']}: counter {counter} != TX1/RX0 {want_c}"
                    )
                receiver = peer_node if local_side == 2 else local_node
                fp = _dual_ns_fp12(
                    receiver, layer, int(iff["membership_epoch"]), local_side
                )
                if val[52:64] != fp:
                    raise ExpectedModelError(
                        f"{role_name} {entry['identity']}: ns_fingerprint mismatch"
                    )
                if val[24:40] != ck[8:24]:
                    raise ExpectedModelError(
                        f"{role_name} {entry['identity']}: binding prefix mismatch"
                    )
            if mk == 2:
                al_count += 1
                floor = int.from_bytes(val[8:12], "big")
                want_f = context_id + 1
                if floor != want_f:
                    raise ExpectedModelError(
                        f"{role_name} {entry['identity']}: AL floor {floor} != context_id+1 {want_f}"
                    )
                if context_id in expected_floors and floor != expected_floors[context_id]:
                    raise ExpectedModelError(
                        f"{role_name}: expected floor pin {expected_floors[context_id]}"
                    )
        if lane_count != 6 or al_count != 4:
            raise ExpectedModelError(
                f"{role_name}: lane/al counts {lane_count}/{al_count}"
            )

        # OLD cardinality is row data, not a fixed protocol constant.
        old = document["lifecycle"]["group_machine"]["snapshots"]["roles"][
            role_name
        ]["exact_old"]
        if int(old["member_count"]) != len(old["members"]):
            raise ExpectedModelError(
                f"{role_name}: OLD count/member mismatch"
            )
        if not 1 <= len(old["members"]) <= 14:
            raise ExpectedModelError(f"{role_name}: OLD count domain")
        if not any(int(m["member_kind"]) == 1 for m in old["members"]):
            raise ExpectedModelError(f"{role_name}: legal lane OLD not exercised")
        rows = document["lifecycle"]["group_machine"]["snapshots"]["roles"][
            role_name
        ]["write_set_rows"]
        if len(rows) != 15:
            raise ExpectedModelError(f"{role_name}: write_set_rows != 15")
        if sum(1 for row in rows if row["old_present"]) != len(old["members"]):
            raise ExpectedModelError(f"{role_name}: per-row OLD presence mismatch")
        cases = document["lifecycle"]["group_machine"]["snapshots"]["roles"][
            role_name
        ]["cu_row_classifier_cases"]
        if [case["expected_classification"] for case in cases] != [
            "OLD",
            "NEW",
            "STABLE",
            "THIRD",
        ]:
            raise ExpectedModelError(f"{role_name}: CU row matrix")
    gm = document["lifecycle"]["group_machine"]
    if gm["old_count_is_protocol_constant"] is not False:
        raise ExpectedModelError("OLD count must not be a protocol constant")
    monotonic = document["lifecycle"]["group_machine"]["snapshots"][
        "reattach_10k_restart"
    ]
    if (
        monotonic["cycles"] != 10_000
        or monotonic["restart_after_each_cycle"] is not True
        or monotonic["regression_count"] != 0
    ):
        raise ExpectedModelError("reattach 10k monotonic model")


def assert_carrier_negatives_independent(document: dict[str, Any]) -> None:
    """Recompute every non-rejected carrier negative digest from preimage."""
    ct = document["carrier_transcript"]
    primary = ct["primary_path"]
    base = bytes.fromhex(primary["digest_hex"])
    # Independent base: SHA-256(primary preimage), not vector self-trust alone.
    base_pre = bytes.fromhex(primary["preimage_hex"])
    if _dual_sha256(base_pre) != base:
        raise ExpectedModelError("carrier primary digest dual recompute")
    if base.hex() != primary["preimage_sha256"] and _dual_sha256(base_pre).hex() != primary[
        "preimage_sha256"
    ]:
        if _dual_sha256(base_pre).hex() != primary["preimage_sha256"]:
            raise ExpectedModelError("carrier primary preimage_sha256")
    label = ct["label"].encode("ascii")
    if len(label) != 31 or label != b"NINLIL-PA-CARRIER-TRANSCRIPT-V1":
        raise ExpectedModelError(f"carrier label len/value {len(label)}")
    # Preimage must start with exact 31-octet label.
    if not base_pre.startswith(label):
        raise ExpectedModelError("carrier preimage label prefix")
    for neg in ct["negatives"]:
        if neg.get("rejected"):
            continue
        pre = bytes.fromhex(neg["preimage_hex"])
        dig = _dual_sha256(pre)
        if dig != bytes.fromhex(neg["digest_hex"]) or dig == base:
            raise ExpectedModelError(f"carrier negative {neg['id']} dual recompute")
        if _dual_sha256(pre).hex() != neg["preimage_sha256"]:
            raise ExpectedModelError(f"carrier negative {neg['id']} preimage_sha256")


def build_expected_document(*, use_cache: bool = True) -> dict[str, Any]:
    """Load the independently pinned mutation-campaign baseline.

    This function intentionally cannot rebuild through composition.  The byte
    pin catches fixture edits, the generator freshness gate catches emission
    drift, and ``independent_authority`` executes the actual semantics.
    """
    global _EXPECTED_CACHE
    if use_cache and _EXPECTED_CACHE is not None:
        return copy.deepcopy(_EXPECTED_CACHE)
    raw = _EXPECTED_VECTOR.read_bytes()
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != EXPECTED_VECTOR_SHA256:
        raise ExpectedModelError(
            "independent expected vector SHA mismatch "
            f"actual={actual_sha} expected={EXPECTED_VECTOR_SHA256}"
        )
    document = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
    )
    if not isinstance(document, dict):
        raise ExpectedModelError("expected vector root not object")
    from production_attachment_edhoc_independent_authority import (
        assert_independent_authority_closed,
    )
    try:
        assert_independent_authority_closed(document)
    except Exception as err:
        raise ExpectedModelError(
            f"pinned vector fails independent authority: {err}"
        ) from err
    if use_cache:
        _EXPECTED_CACHE = document
        return copy.deepcopy(_EXPECTED_CACHE)
    return document


def path_is_descriptive(path: str) -> bool:
    if path in DESCRIPTIVE_ALLOWLIST_PATHS:
        return True
    # Leaf name allowlist only for the known free prose keys.
    leaf = path.rsplit(".", 1)[-1]
    if leaf in DESCRIPTIVE_ALLOWLIST_TOKENS and path in DESCRIPTIVE_ALLOWLIST_PATHS:
        return True
    return path in DESCRIPTIVE_ALLOWLIST_PATHS


def _path_join(parent: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{parent}[{key}]"
    if parent == "$":
        return f"$.{key}"
    return f"{parent}.{key}"


def mask_descriptive(document: Any, path: str = "$") -> Any:
    """Deep-copy tree with allowlisted descriptive leaves replaced by a pin."""
    if path_is_descriptive(path):
        return "<DESCRIPTIVE_ALLOWLIST>"
    if isinstance(document, dict):
        return {
            k: mask_descriptive(v, _path_join(path, k)) for k, v in document.items()
        }
    if isinstance(document, list):
        return [
            mask_descriptive(v, _path_join(path, i)) for i, v in enumerate(document)
        ]
    return document


def deep_diff(
    actual: Any,
    expected: Any,
    *,
    path: str = "$",
    max_diffs: int = 50,
) -> list[str]:
    """Field-by-field equality; descriptive allowlist paths are ignored."""
    diffs: list[str] = []

    def add(message: str) -> None:
        if len(diffs) < max_diffs:
            diffs.append(message)

    def walk(a: Any, e: Any, p: str) -> None:
        if len(diffs) >= max_diffs:
            return
        if path_is_descriptive(p):
            return
        if type(a) is not type(e) and not (
            # JSON numbers are all int in our strict loader; keep exact type.
            False
        ):
            # bool is subclass of int in Python — reject bool/int mix earlier.
            if type(a) is not type(e):
                add(f"{p}: type {type(a).__name__} != {type(e).__name__}")
                return
        if isinstance(e, dict):
            if not isinstance(a, dict):
                add(f"{p}: expected object")
                return
            a_keys = set(a.keys())
            e_keys = set(e.keys())
            for k in sorted(e_keys - a_keys):
                add(f"{p}.{k}: missing in actual")
            for k in sorted(a_keys - e_keys):
                add(f"{p}.{k}: unexpected key in actual")
            for k in sorted(a_keys & e_keys):
                walk(a[k], e[k], _path_join(p, k))
            return
        if isinstance(e, list):
            if not isinstance(a, list):
                add(f"{p}: expected array")
                return
            if len(a) != len(e):
                add(f"{p}: length {len(a)} != {len(e)}")
            for i, (av, ev) in enumerate(zip(a, e)):
                walk(av, ev, _path_join(p, i))
            return
        if a != e:
            # Truncate long hex for readability.
            def fmt(v: Any) -> str:
                s = repr(v)
                return s if len(s) <= 96 else s[:93] + "..."

            add(f"{p}: {fmt(a)} != {fmt(e)}")

    walk(actual, expected, path)
    return diffs


def assert_document_matches_expected(
    actual: dict[str, Any],
    *,
    expected: dict[str, Any] | None = None,
    run_independent_authority: bool = True,
    run_adversarial_campaign: bool = True,
) -> None:
    """Dual authority: independent formulas + full machine-tree equality.

    The full-tree comparison runs first so an exhaustive leaf campaign can
    reject a drift without re-running the expensive semantic authority for
    every leaf.  Default callers still run both independent checks after an
    exact tree match:

    1) full closed-tree equality vs the separately SHA-pinned vector baseline;
    2) verify_oracle+seeds rebuild both-role images (not derived from gen helpers);
    3) repaired CRC/digest adversarial must reject.

    The two boolean switches are only for a mutation campaign that supplies a
    pre-authorized ``expected`` tree.  Production/vector validation must retain
    their default ``True`` values.
    """
    if expected is None:
        expected = build_expected_document()
    diffs = deep_diff(actual, expected)
    if diffs:
        preview = "\n  ".join(diffs[:20])
        raise ExpectedModelError(
            f"canonical expected-model mismatch ({len(diffs)} diffs):\n  {preview}"
        )

    if not run_independent_authority and run_adversarial_campaign:
        raise ExpectedModelError(
            "adversarial campaign requires independent authority"
        )
    if not run_independent_authority:
        return

    try:
        from production_attachment_edhoc_independent_authority import (
            assert_independent_authority_closed,
            run_repaired_crc_digest_adversarial,
        )

        assert_independent_authority_closed(actual)
        if run_adversarial_campaign:
            n = run_repaired_crc_digest_adversarial(actual)
            if n < 16:
                raise ExpectedModelError(f"repaired CRC/digest adversarial trials {n}")
    except Exception as err:
        if type(err).__name__ == "AuthorityError" or isinstance(
            err, ExpectedModelError
        ):
            raise ExpectedModelError(str(err)) from err
        raise ExpectedModelError(str(err)) from err


def canonical_json_bytes(document: dict[str, Any]) -> bytes:
    """Canonical serialization (sorted keys) after descriptive masking."""
    masked = mask_descriptive(document)
    return (
        json.dumps(masked, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def assert_canonical_serialization_match(
    actual: dict[str, Any],
    *,
    expected: dict[str, Any] | None = None,
) -> None:
    """Masked canonical serialization must match the pinned baseline."""
    if expected is None:
        expected = build_expected_document()
    a = canonical_json_bytes(actual)
    e = canonical_json_bytes(expected)
    if a != e:
        ah = hashlib.sha256(a).hexdigest()
        eh = hashlib.sha256(e).hexdigest()
        raise ExpectedModelError(
            f"canonical serialization mismatch sha actual={ah} expected={eh}"
        )


def iter_scalar_leaves(
    document: Any, path: str = "$"
) -> Iterable[tuple[str, Any]]:
    if isinstance(document, dict):
        for k, v in document.items():
            yield from iter_scalar_leaves(v, _path_join(path, k))
    elif isinstance(document, list):
        for i, v in enumerate(document):
            yield from iter_scalar_leaves(v, _path_join(path, i))
    else:
        yield path, document


def type_preserving_mutate(value: Any) -> Any | None:
    """Return a type-preserving scalar mutation, or None if not mutatable."""
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        if not value:
            return "X"
        if all(c in "0123456789abcdef" for c in value) and len(value) % 2 == 0:
            return ("0" if value[0] != "0" else "1") + value[1:]
        return value + "_DRIFT"
    return None


def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
    assert path.startswith("$.")
    parts: list[str | int] = []
    i = 2
    cur = ""
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if cur:
                parts.append(cur)
                cur = ""
            i += 1
        elif ch == "[":
            if cur:
                parts.append(cur)
                cur = ""
            j = path.index("]", i)
            parts.append(int(path[i + 1 : j]))
            i = j + 1
        else:
            cur += ch
            i += 1
    if cur:
        parts.append(cur)
    obj: Any = document
    for part in parts[:-1]:
        obj = obj[part]
    obj[parts[-1]] = value


def run_machine_leaf_mutation_campaign(
    *,
    validate: Callable[[dict[str, Any]], Any],
    document: dict[str, Any] | None = None,
    include_unknown_key_probe: bool = True,
) -> dict[str, Any]:
    """Mutate every machine scalar leaf; every mutation must reject.

    Descriptive allowlist paths may accept. Unknown-key injection on every
    object path is optional and expected to reject when closed schema is on.
    """
    if document is None:
        document = build_expected_document()
    leaves = list(iter_scalar_leaves(document))
    accepted: list[str] = []
    tested = 0
    for path, original in leaves:
        mut = type_preserving_mutate(original)
        if mut is None or mut == original:
            continue
        tested += 1
        changed = copy.deepcopy(document)
        _set_path(changed, path, mut)
        try:
            validate(changed)
        except Exception:
            continue
        if path_is_descriptive(path):
            continue
        accepted.append(path)

    unknown_key_accepted: list[str] = []
    unknown_key_tested = 0
    if include_unknown_key_probe:

        def walk_objects(obj: Any, path: str) -> Iterable[tuple[str, Any]]:
            if isinstance(obj, dict):
                yield path, obj
                for k, v in obj.items():
                    yield from walk_objects(v, _path_join(path, k))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    yield from walk_objects(v, _path_join(path, i))

        for path, obj in walk_objects(document, "$"):
            unknown_key_tested += 1
            changed = copy.deepcopy(document)
            # Locate object again and inject.
            target = changed
            if path != "$":
                # Re-set via path walk on changed.
                parts: list[str | int] = []
                i = 2
                cur = ""
                while i < len(path):
                    ch = path[i]
                    if ch == ".":
                        if cur:
                            parts.append(cur)
                            cur = ""
                        i += 1
                    elif ch == "[":
                        if cur:
                            parts.append(cur)
                            cur = ""
                        j = path.index("]", i)
                        parts.append(int(path[i + 1 : j]))
                        i = j + 1
                    else:
                        cur += ch
                        i += 1
                if cur:
                    parts.append(cur)
                for part in parts:
                    target = target[part]
            if not isinstance(target, dict):
                continue
            target["__campaign_unknown_key__"] = True
            try:
                validate(changed)
                unknown_key_accepted.append(path)
            except Exception:
                pass

    result = {
        "scalar_leaves_seen": len(leaves),
        "scalar_mutations_tested": tested,
        "machine_false_greens": accepted,
        "machine_false_green_count": len(accepted),
        "unknown_key_paths_tested": unknown_key_tested,
        "unknown_key_accepted": unknown_key_accepted,
        "unknown_key_accepted_count": len(unknown_key_accepted),
        "descriptive_allowlist": sorted(DESCRIPTIVE_ALLOWLIST_PATHS),
        "status": "PASS"
        if not accepted and not unknown_key_accepted
        else "FAIL",
    }
    if result["status"] != "PASS":
        raise ExpectedModelError(
            "mutation campaign FAIL machine_false_greens="
            f"{len(accepted)} unknown_key_accepted={len(unknown_key_accepted)} "
            f"sample={accepted[:8]}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PA-S0 independent expected-model authority"
    )
    parser.add_argument(
        "--dump-json",
        action="store_true",
        help="print rebuilt expected document as JSON",
    )
    parser.add_argument(
        "--dump-canonical-sha256",
        action="store_true",
        help="print SHA-256 of masked canonical serialization",
    )
    parser.add_argument(
        "--check-vector",
        type=Path,
        default=None,
        help="compare on-disk vector to independent rebuild (allowlist prose)",
    )
    args = parser.parse_args()
    try:
        expected = build_expected_document()
        if args.dump_json:
            sys.stdout.write(
                json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n"
            )
        if args.dump_canonical_sha256:
            digest = hashlib.sha256(canonical_json_bytes(expected)).hexdigest()
            print(digest)
        if args.check_vector is not None:
            text = args.check_vector.read_text(encoding="utf-8")
            actual = json.loads(text)
            if not isinstance(actual, dict):
                raise ExpectedModelError("vector root not object")
            assert_document_matches_expected(actual, expected=expected)
            assert_canonical_serialization_match(actual, expected=expected)
            print(
                "expected-model OK "
                f"sha256={hashlib.sha256(args.check_vector.read_bytes()).hexdigest()}"
            )
        if not args.dump_json and not args.dump_canonical_sha256 and args.check_vector is None:
            parser.print_help()
            return 2
    except (OSError, json.JSONDecodeError, ExpectedModelError) as error:
        print(f"expected-model FAIL: {error}", file=sys.stderr)
        return 1
    return 0




def run_repaired_digest_adversarial_campaign(document: dict[str, Any]) -> int:
    """Mutate complete keys / floors / carrier digests; dual oracle must reject."""
    import copy as _copy

    trials = 0
    # 1) repaired complete-key digest (binding flip)
    bad = _copy.deepcopy(document)
    inv = bad["atomic_batch_manifests"]["device_local_role_1"]["exact_inventory"]
    lane = next(e for e in inv if int(e["member_kind"]) == 1)
    ck = bytearray(bytes.fromhex(lane["complete_key_hex"]))
    ck[8] ^= 0x01  # binding_digest byte
    lane["complete_key_hex"] = bytes(ck).hex()
    trials += 1
    try:
        assert_role_images_match_docs30_dual(bad)
        raise ExpectedModelError("repaired complete-key accepted")
    except ExpectedModelError as err:
        if "accepted" in str(err):
            raise

    # 2) AL floor repaired to key_generation (false-green candidate)
    bad2 = _copy.deepcopy(document)
    inv2 = bad2["atomic_batch_manifests"]["device_local_role_1"]["exact_inventory"]
    al = next(e for e in inv2 if int(e["member_kind"]) == 2)
    v = bytearray(bytes.fromhex(al["value_hex"]))
    kg = int(al["key_generation"]) & 0xFFFFFFFF
    v[8:12] = kg.to_bytes(4, "big")
    # leave CRC wrong intentionally; dual floor check fires before CRC
    al["value_hex"] = bytes(v).hex()
    trials += 1
    try:
        assert_role_images_match_docs30_dual(bad2)
        raise ExpectedModelError("repaired AL floor accepted")
    except ExpectedModelError as err:
        if "accepted" in str(err):
            raise

    # 3) carrier negative digest repaired to match base (must fail dual)
    bad3 = _copy.deepcopy(document)
    base = bad3["carrier_transcript"]["primary_path"]["digest_hex"]
    for neg in bad3["carrier_transcript"]["negatives"]:
        if not neg.get("rejected"):
            neg["digest_hex"] = base  # repaired to collide with base
            break
    trials += 1
    try:
        assert_carrier_negatives_independent(bad3)
        raise ExpectedModelError("repaired carrier negative accepted")
    except ExpectedModelError as err:
        if "accepted" in str(err):
            raise

    # 4) OLD presents a lane (14-style false green)
    bad4 = _copy.deepcopy(document)
    role = bad4["lifecycle"]["group_machine"]["snapshots"]["roles"][
        "device_local_role_1"
    ]
    lane_row = next(
        e
        for e in bad4["atomic_batch_manifests"]["device_local_role_1"]["exact_inventory"]
        if int(e["member_kind"]) == 1
    )
    role["exact_old"]["members"].append(
        {
            "index": lane_row["index"],
            "identity": lane_row["identity"],
            "member_kind": 1,
            "complete_key_hex": lane_row["complete_key_hex"],
            "complete_key_length": lane_row["complete_key_length"],
            "value_hex": lane_row["value_hex"],
            "value_sha256": lane_row["value_sha256"],
            "value_bytes": lane_row["value_bytes"],
            "context_digest_hex": lane_row["context_digest_hex"],
        }
    )
    role["exact_old"]["member_count"] = len(role["exact_old"]["members"])
    trials += 1
    try:
        assert_role_images_match_docs30_dual(bad4)
        raise ExpectedModelError("OLD lane present accepted")
    except ExpectedModelError as err:
        if "accepted" in str(err):
            raise
    return trials

if __name__ == "__main__":
    raise SystemExit(main())
