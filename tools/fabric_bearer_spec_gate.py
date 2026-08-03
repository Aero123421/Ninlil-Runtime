#!/usr/bin/env python3
"""Independent Python + Node gate for the ADR-0017 candidate vectors.

This gate does not import the vector generator or production Ninlil code.
It re-parses durable bytes, re-runs selection decisions, and asks Node.js to
independently verify the canonical durable envelope/digest rules.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "spec/vectors/fabric-bearer-spec-v1.json"
GENERATOR = ROOT / "tools/fabric_bearer_spec_vector_gen.py"

ACTUAL_SELECTION_IDS = (
    "FABRIC-SELECT-ACTUAL-JOIN-BASELINE",
    "FABRIC-SELECT-POLICY-NO-MATCH",
    "FABRIC-SELECT-POLICY-AMBIGUOUS",
    "FABRIC-SELECT-POLICY-REVISION-GAP",
    "FABRIC-SELECT-REGISTRY-JOIN-MISSING",
    "FABRIC-SELECT-AUTHORITY-JOIN-MISSING",
    "FABRIC-SELECT-AUTHORITY-JOIN-AMBIGUOUS",
    "FABRIC-SELECT-LIFECYCLE-DRAINING",
    "FABRIC-SELECT-DIRECTION-MISMATCH",
    "FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR",
    "FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING",
    "FABRIC-SELECT-LATENCY-CLASS",
    "FABRIC-SELECT-COST-CLASS",
    "FABRIC-SELECT-DEADLINE-GUARD",
    "FABRIC-SELECT-RETRY-LIFETIME-CLOCK-EPOCH",
    "FABRIC-SELECT-RESERVATION-CAPACITY",
    "FABRIC-SELECT-CAPABILITY-MISSING",
    "FABRIC-SELECT-ENERGY-SLEEP-CAPABILITY-MISSING",
    "FABRIC-SELECT-SECURITY-MISSING",
    "FABRIC-SELECT-CUSTODY-MISSING",
    "FABRIC-SELECT-EVIDENCE-MISSING",
    "FABRIC-SELECT-PEER-NFL1-UNSUPPORTED",
    "FABRIC-SELECT-AUTHENTICATED-PEER-MISMATCH",
    "FABRIC-SELECT-ATTACHMENT-AUTHORITY-MISMATCH",
    "FABRIC-SELECT-ATTACHMENT-BINDING-MISMATCH",
    "FABRIC-SELECT-ATTESTATION-EPOCH",
    "FABRIC-SELECT-ATTESTATION-EXPIRED",
    "FABRIC-SELECT-AVAILABILITY-EPOCH",
    "FABRIC-SELECT-AVAILABILITY-STATE",
    "FABRIC-SELECT-AVAILABILITY-EXPIRED",
    "FABRIC-SELECT-AUTHORITY-CLOCK-EPOCH",
    "FABRIC-SELECT-AUTHORITY-LEASE-EXPIRED",
    "FABRIC-SELECT-META-OUTER-UNAVAILABLE",
    "FABRIC-SELECT-SOURCE-RUNTIME-ENDPOINT",
    "FABRIC-SELECT-ABSENT-ALLOWED",
    "FABRIC-SELECT-BOUND-REQUIRED-ABSENT",
    "FABRIC-SELECT-MTU-BASELINE",
    "FABRIC-SELECT-PACKET-MTU",
    "FABRIC-SELECT-TRANSFER-MTU",
    "FABRIC-SELECT-PACKET-MINIMUM",
    "FABRIC-SELECT-RF-MAPPING-BASELINE",
    "FABRIC-SELECT-RF-MAPPING-UNSUPPORTED",
    "FABRIC-SELECT-RF-NO-PERMIT",
    "FABRIC-SELECT-SAME-KIND-TWO-INSTANCES",
    "FABRIC-SELECT-STABLE-ID-TIEBREAK",
    "FABRIC-SELECT-HARD-FILTER-PRECEDENCE",
)

# Absolute NFL1 structural admission range for selection hard filters.
NFL1_STRUCTURAL_MIN = 587
NFL1_STRUCTURAL_MAX = 1925
# Authoritative Fabric storage CU budgets (ADR-0017 / vector constants).
FABRIC_COMMITTED_CU_BYTES = 137940
FABRIC_FULL_STAGING_CU_BYTES = 275880
# Obsolete published drift — must never reappear.
FABRIC_OBSOLETE_CU_BYTES = frozenset(
    {134612, 136148, 269224, 272296}
)

SELECTION_RACE_CASES: dict[str, dict[str, Any]] = {
    "FABRIC-SELECT-AVAILABILITY-EPOCH-RACE": {
        "event": "AVAILABILITY_EPOCH_CHANGED_BEFORE_PROVIDER_RETAIN",
        "admission_epoch": 7,
        "pre_retain_epoch": 8,
        "provider_retained": 0,
        "provider_start_calls": 0,
        "same_attempt_reselect_calls": 0,
        "closed_full_replacement": 1,
        "result": "UNAVAILABLE_NO_RETAIN_NO_SAME_ATTEMPT_RESELECT",
    },
    "FABRIC-SELECT-POST-RETAIN-EPOCH-RACE": {
        "event": "AVAILABILITY_EPOCH_CHANGED_AFTER_PROVIDER_RETAIN",
        "fabric_retained_epoch": 7,
        "post_provider_retain_epoch": 8,
        "provider_retained": 1,
        "provider_start_calls": 1,
        "same_attempt_reselect_calls": 0,
        "track_provider_token_to_terminal": 1,
        "result": "ACCEPTED_TRACK_PROVIDER_TOKEN_TO_TERMINAL",
    },
}

HARD_FILTER_ORDER = (
    'LIFECYCLE_DRAINING',
    'DIRECTION_MISMATCH',
    'STRUCTURAL_LENGTH_FLOOR',
    'STRUCTURAL_LENGTH_CEILING',
    'PACKET_MINIMUM',
    'PACKET_MTU',
    'TRANSFER_MTU',
    'LATENCY_CLASS',
    'COST_CLASS',
    'DEADLINE_GUARD',
    'RETRY_LIFETIME_CLOCK_EPOCH',
    'RESERVATION_CAPACITY',
    'CAPABILITY_MISSING',
    'ENERGY_SLEEP_CAPABILITY_MISSING',
    'SECURITY_MISSING',
    'CUSTODY_MISSING',
    'EVIDENCE_MISSING',
    'PEER_NFL1',
    'AUTHENTICATED_PEER_MISMATCH',
    'ATTACHMENT_AUTHORITY_MISMATCH',
    'ATTACHMENT_BINDING_MISMATCH',
    'ATTESTATION_EPOCH',
    'ATTESTATION_EXPIRED',
    'AVAILABILITY_EPOCH',
    'AVAILABILITY_STATE',
    'AVAILABILITY_EXPIRED',
    'BOUND_REQUIRED_ABSENT',
    'AUTHORITY_CLOCK_EPOCH',
    'AUTHORITY_LEASE_EXPIRED',
    'RF_PERMIT',
    'RF_MAPPING_UNSUPPORTED',
)

# Independent ID→semantic authority (not derived from vector model at runtime).
SELECTION_SEMANTICS: dict[str, dict[str, Any]] = {
    'FABRIC-SELECT-ABSENT-ALLOWED': {
        'authority_count': 1,
        'authority_mode': 'ABSENT_ALLOWED',
        'authority_state': 'ABSENT',
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 1,
        'resolution': 'SELECTED',
        'selected_instance_id_hex': '6162636465666768696a6b6c6d6e6f70',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-ACTUAL-JOIN-BASELINE': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 1,
        'resolution': 'SELECTED',
        'selected_instance_id_hex': '6162636465666768696a6b6c6d6e6f70',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-ATTACHMENT-AUTHORITY-MISMATCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 19,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': '42434445464748494a4b4c4d4e4f5051',
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'attachment_authority_id_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'ATTACHMENT_AUTHORITY_MISMATCH',
        'registry_count': 1,
        'rejection_reasons': ['ATTACHMENT_AUTHORITY_MISMATCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-ATTACHMENT-BINDING-MISMATCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 20,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'cd204b528c0eed26f15d4d5d718c1b174b5e59940920016227a1730e22ffed37',
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'attachment_binding_digest_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'ATTACHMENT_BINDING_MISMATCH',
        'registry_count': 1,
        'rejection_reasons': ['ATTACHMENT_BINDING_MISMATCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-ATTESTATION-EPOCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 21,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'a2a3a4a5a6a7a8a9aaabacadaeafb0b1',
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'attestation_clock_epoch_id_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'ATTESTATION_EPOCH',
        'registry_count': 1,
        'rejection_reasons': ['ATTESTATION_EPOCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-ATTESTATION-EXPIRED': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 22,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 100000,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'attestation_expires_at_ms'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'ATTESTATION_EXPIRED',
        'registry_count': 1,
        'rejection_reasons': ['ATTESTATION_EXPIRED'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AUTHENTICATED-PEER-MISMATCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 18,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': '32333435363738393a3b3c3d3e3f4041',
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'authenticated_peer_runtime_id_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AUTHENTICATED_PEER_MISMATCH',
        'registry_count': 1,
        'rejection_reasons': ['AUTHENTICATED_PEER_MISMATCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AUTHORITY-CLOCK-EPOCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 27,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'd2d3d4d5d6d7d8d9dadbdcdddedfe0e1',
        'mutation_op': 'replace',
        'mutation_path': ['authorities', 0, 'authority_clock_epoch_id_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AUTHORITY_CLOCK_EPOCH',
        'registry_count': 1,
        'rejection_reasons': ['AUTHORITY_CLOCK_EPOCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AUTHORITY-JOIN-AMBIGUOUS': {
        'authority_binding_ids': ['b8b9babbbcbdbebfc0c1c2c3c4c5c6c7', 'b9babbbcbdbebfc0c1c2c3c4c5c6c7c8'],
        'authority_count': 2,
        'authority_policy_ids': ['7172737475767778797a7b7c7d7e7f80', '7172737475767778797a7b7c7d7e7f80'],
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_op': 'append',
        'mutation_path': ['authorities'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AUTHORITY_JOIN_AMBIGUOUS',
        'registry_count': 1,
        'rejection_reasons': ['AUTHORITY_JOIN_AMBIGUOUS'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AUTHORITY-JOIN-MISSING': {
        'authority_count': 0,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_op': 'remove',
        'mutation_path': ['authorities'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AUTHORITY_JOIN_MISSING',
        'registry_count': 1,
        'rejection_reasons': ['AUTHORITY_JOIN_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AUTHORITY-LEASE-EXPIRED': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 28,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 100000,
        'mutation_op': 'replace',
        'mutation_path': ['authorities', 0, 'lease_expires_at_ms'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AUTHORITY_LEASE_EXPIRED',
        'registry_count': 1,
        'rejection_reasons': ['AUTHORITY_LEASE_EXPIRED'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AVAILABILITY-EPOCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 23,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'a2a3a4a5a6a7a8a9aaabacadaeafb0b1',
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'availability_clock_epoch_id_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AVAILABILITY_EPOCH',
        'registry_count': 1,
        'rejection_reasons': ['AVAILABILITY_EPOCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AVAILABILITY-EXPIRED': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 25,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 100000,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'availability_expires_at_ms'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AVAILABILITY_EXPIRED',
        'registry_count': 1,
        'rejection_reasons': ['AVAILABILITY_EXPIRED'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-AVAILABILITY-STATE': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 24,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 0,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'availability_state'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'AVAILABILITY_STATE',
        'registry_count': 1,
        'rejection_reasons': ['AVAILABILITY_STATE'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-BOUND-REQUIRED-ABSENT': {
        'authority_count': 1,
        'authority_mode': 'BOUND_REQUIRED',
        'authority_state': 'ABSENT',
        'direction_mask': 3,
        'filter_index': 26,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'BOUND_REQUIRED',
        'mutation_op': 'replace',
        'mutation_path': ['policies', 0, 'authority_mode'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'BOUND_REQUIRED_ABSENT',
        'registry_count': 1,
        'rejection_reasons': ['BOUND_REQUIRED_ABSENT'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-CAPABILITY-MISSING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 12,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 109,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'capability_flags'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'CAPABILITY_MISSING',
        'registry_count': 1,
        'rejection_reasons': ['CAPABILITY_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-COST-CLASS': {
        'authority_count': 1,
        'cost_class': 51,
        'direction_mask': 3,
        'filter_index': 8,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 51,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'cost_class'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'COST_CLASS',
        'registry_count': 1,
        'rejection_reasons': ['COST_CLASS'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-CUSTODY-MISSING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 15,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 79,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'capability_flags'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'CUSTODY_MISSING',
        'registry_count': 1,
        'rejection_reasons': ['CUSTODY_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-DEADLINE-GUARD': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 9,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 100099,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'deadline_ms'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'DEADLINE_GUARD',
        'registry_count': 1,
        'rejection_reasons': ['DEADLINE_GUARD'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-DIRECTION-MISMATCH': {
        'authority_count': 1,
        'direction_mask': 2,
        'filter_index': 1,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 2,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'direction_mask'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'DIRECTION_MISMATCH',
        'registry_count': 1,
        'rejection_reasons': ['DIRECTION_MISMATCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-ENERGY-SLEEP-CAPABILITY-MISSING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 13,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 110,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'capability_flags'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'ENERGY_SLEEP_CAPABILITY_MISSING',
        'registry_count': 1,
        'rejection_reasons': ['ENERGY_SLEEP_CAPABILITY_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-EVIDENCE-MISSING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 16,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 47,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'capability_flags'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'EVIDENCE_MISSING',
        'registry_count': 1,
        'rejection_reasons': ['EVIDENCE_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-HARD-FILTER-PRECEDENCE': {
        'authority_count': 1,
        'direction_mask': 2,
        'filter_index': 0,
        'lifecycle': 'DRAINING',
        'maximum_packet_bytes': 587,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 586,
        'policy_count': 1,
        'primary_rejection': 'LIFECYCLE_DRAINING',
        'registry_count': 1,
        'rejection_reasons': ['LIFECYCLE_DRAINING', 'DIRECTION_MISMATCH', 'STRUCTURAL_LENGTH_FLOOR', 'PACKET_MINIMUM', 'SECURITY_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'security_capability_flags': 0,
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-LATENCY-CLASS': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 7,
        'latency_class': 51,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 51,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'latency_class'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'LATENCY_CLASS',
        'registry_count': 1,
        'rejection_reasons': ['LATENCY_CLASS'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-LIFECYCLE-DRAINING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 0,
        'lifecycle': 'DRAINING',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'DRAINING',
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'lifecycle'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'LIFECYCLE_DRAINING',
        'registry_count': 1,
        'rejection_reasons': ['LIFECYCLE_DRAINING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-META-OUTER-UNAVAILABLE': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 0,
        'mutation_op': 'replace',
        'mutation_path': ['meta', 'outer_available'],
        'outer_available': 0,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'META_OUTER_UNAVAILABLE',
        'registry_count': 1,
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-MTU-BASELINE': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 587,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 1,
        'resolution': 'SELECTED',
        'selected_instance_id_hex': '6162636465666768696a6b6c6d6e6f70',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-PACKET-MINIMUM': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 4,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 600,
        'mutation_new': 600,
        'mutation_op': 'replace',
        'mutation_path': ['policies', 0, 'minimum_packet_bytes'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'PACKET_MINIMUM',
        'registry_count': 1,
        'rejection_reasons': ['PACKET_MINIMUM'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-PACKET-MTU': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 5,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 587,
        'minimum_packet_bytes': 587,
        'mutation_new': 588,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'packet_bytes'],
        'outer_available': 1,
        'packet_bytes': 588,
        'policy_count': 1,
        'primary_rejection': 'PACKET_MTU',
        'registry_count': 1,
        'rejection_reasons': ['PACKET_MTU'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-PEER-NFL1-UNSUPPORTED': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 17,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 2,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'peer_nfl1_version'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'PEER_NFL1',
        'registry_count': 1,
        'rejection_reasons': ['PEER_NFL1'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-POLICY-AMBIGUOUS': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_op': 'append',
        'mutation_path': ['policies'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 2,
        'primary_rejection': 'POLICY_AMBIGUOUS',
        'registry_count': 1,
        'resolution': 'CORRUPT',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-POLICY-NO-MATCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': '67da0ab19cf2bab070be081de4a661d9e7415cb0e151e110d9f7490ff1fca07a',
        'mutation_op': 'replace',
        'mutation_path': ['query', 'service_identity_digest_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'POLICY_NO_MATCH',
        'registry_count': 1,
        'resolution': 'NO_POLICY',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-POLICY-REVISION-GAP': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': [1, 3],
        'mutation_op': 'replace',
        'mutation_path': ['policies', 0, 'revision_chain'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'POLICY_REVISION_GAP',
        'registry_count': 1,
        'resolution': 'CORRUPT',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-REGISTRY-JOIN-MISSING': {
        'authority_count': 1,
        'direction_mask': None,
        'filter_index': None,
        'lifecycle': None,
        'maximum_packet_bytes': None,
        'minimum_packet_bytes': 587,
        'mutation_op': 'remove',
        'mutation_path': ['registry'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'REGISTRY_JOIN_MISSING',
        'registry_count': 0,
        'rejection_reasons': ['REGISTRY_JOIN_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-RESERVATION-CAPACITY': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 11,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_op': 'append',
        'mutation_path': ['active_attempts'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'RESERVATION_CAPACITY',
        'registry_count': 1,
        'rejection_reasons': ['RESERVATION_CAPACITY'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-RETRY-LIFETIME-CLOCK-EPOCH': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 10,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 'a2a3a4a5a6a7a8a9aaabacadaeafb0b1',
        'mutation_op': 'replace',
        'mutation_path': ['query', 'admission_clock_epoch_id_hex'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'RETRY_LIFETIME_CLOCK_EPOCH',
        'registry_count': 1,
        'rejection_reasons': ['RETRY_LIFETIME_CLOCK_EPOCH'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-RF-MAPPING-BASELINE': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'link_kind': 'RF',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 1,
        'resolution': 'SELECTED',
        'selected_instance_id_hex': '6162636465666768696a6b6c6d6e6f70',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-RF-MAPPING-UNSUPPORTED': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 30,
        'lifecycle': 'ACTIVE',
        'link_kind': 'RF',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': False,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'rf_mapping_accepted'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'RF_MAPPING_UNSUPPORTED',
        'registry_count': 1,
        'rejection_reasons': ['RF_MAPPING_UNSUPPORTED'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'rf_mapping_accepted': False,
        'rf_permit_valid': True,
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-RF-NO-PERMIT': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 29,
        'lifecycle': 'ACTIVE',
        'link_kind': 'RF',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': False,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'rf_permit_valid'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'RF_PERMIT',
        'registry_count': 1,
        'rejection_reasons': ['RF_PERMIT'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'rf_mapping_accepted': True,
        'rf_permit_valid': False,
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-SAME-KIND-TWO-INSTANCES': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 2,
        'resolution': 'SELECTED',
        'selected_instance_id_hex': '6162636465666768696a6b6c6d6e6f70',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-SECURITY-MISSING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 14,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 7,
        'mutation_op': 'replace',
        'mutation_path': ['registry', 0, 'security_capability_flags'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'SECURITY_MISSING',
        'registry_count': 1,
        'rejection_reasons': ['SECURITY_MISSING'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-SOURCE-RUNTIME-ENDPOINT': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 1,
        'resolution': 'SELECTED',
        'scope_selector': 'SOURCE_RUNTIME',
        'selected_instance_id_hex': '6162636465666768696a6b6c6d6e6f70',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-STABLE-ID-TIEBREAK': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': None,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': None,
        'registry_count': 2,
        'resolution': 'SELECTED',
        'selected_instance_id_hex': '0102030405060708090a0b0c0d0e0f10',
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 3,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 1926,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'packet_bytes'],
        'outer_available': 1,
        'packet_bytes': 1926,
        'policy_count': 1,
        'primary_rejection': 'STRUCTURAL_LENGTH_CEILING',
        'registry_count': 1,
        'rejection_reasons': ['STRUCTURAL_LENGTH_CEILING', 'PACKET_MTU'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 2,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 1925,
        'minimum_packet_bytes': 587,
        'mutation_new': 586,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'packet_bytes'],
        'outer_available': 1,
        'packet_bytes': 586,
        'policy_count': 1,
        'primary_rejection': 'STRUCTURAL_LENGTH_FLOOR',
        'registry_count': 1,
        'rejection_reasons': ['STRUCTURAL_LENGTH_FLOOR', 'PACKET_MINIMUM'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 587,
    },
    'FABRIC-SELECT-TRANSFER-MTU': {
        'authority_count': 1,
        'direction_mask': 3,
        'filter_index': 6,
        'lifecycle': 'ACTIVE',
        'maximum_packet_bytes': 587,
        'minimum_packet_bytes': 587,
        'mutation_new': 588,
        'mutation_op': 'replace',
        'mutation_path': ['query', 'transfer_bytes'],
        'outer_available': 1,
        'packet_bytes': 587,
        'policy_count': 1,
        'primary_rejection': 'TRANSFER_MTU',
        'registry_count': 1,
        'rejection_reasons': ['TRANSFER_MTU'],
        'resolution': 'NO_ELIGIBLE_PATH',
        'selected_instance_id_hex': None,
        'transfer_bytes': 588,
    },
}

REQUIRED_FBA_IDS = {
    "FABRIC-FBA-RETRYABLE-TO-PREPARED",
    "FABRIC-FBA-PREPARED-TO-CLOSED-HARD-RACE",
    "FABRIC-FBA-PREPARED-TO-CLOSED-RELEASE",
    "FABRIC-FBA-PREPARED-TO-FENCED-RESTART",
    "FABRIC-FBA-LINK-RETAINED-TO-FENCED-RESTART",
    "FABRIC-FBA-RETRYABLE-RESTART-BEFORE-EXPIRY",
    "FABRIC-FBA-RETRYABLE-RESTART-AT-EXPIRY",
}

FBA_CASES: dict[str, tuple[tuple[int, int], dict[str, Any]]] = {
    "FABRIC-FBA-PREPARED-TO-LINK-RETAINED": (
        (1, 2),
        {
            "cause": "PROVIDER_RETAINED",
            "outer_result": "OK_SEND_ACCEPTED",
            "permit_claim_after": 1,
            "permit_claim_before": 1,
        },
    ),
    "FABRIC-FBA-PREPARED-TO-RETRYABLE": (
        (1, 3),
        {
            "cause": "PROVIDER_WOULD_BLOCK",
            "outer_result": "WOULD_BLOCK",
            "permit_claim_after": 0,
            "permit_claim_before": 1,
            "release_tentative_resources": 1,
        },
    ),
    "FABRIC-FBA-RETRYABLE-TO-PREPARED": (
        (3, 1),
        {
            "cause": "EXACT_RETRY_BEFORE_DURABLE_EXPIRY",
            "fresh_permit_pair": 1,
            "permit_claim_after": 1,
            "permit_claim_before": 0,
            "provider_start_calls_after_commit": 1,
            "registry_authority_snapshot_match": 1,
            "retry_expires_at_ms": 200000,
            "retry_now_ms": 199999,
        },
    ),
    "FABRIC-FBA-PREPARED-TO-CLOSED-HARD-RACE": (
        (1, 4),
        {
            "cause": "PRE_START_HARD_GATE_CHANGED",
            "outer_result": "UNAVAILABLE_OR_DENIED",
            "permit_claim_after": 0,
            "permit_claim_before": 0,
            "provider_start_calls": 0,
        },
    ),
    "FABRIC-FBA-PREPARED-TO-CLOSED-RELEASE": (
        (1, 4),
        {
            "cause": "RUNTIME_DISPATCH_RELEASE_BEFORE_START",
            "followup_transition": "CLOSED_TO_DRAINED",
            "permit_claim_after": 0,
            "permit_claim_before": 0,
            "provider_start_calls": 0,
        },
    ),
    "FABRIC-FBA-LINK-RETAINED-TO-CLOSED": (
        (2, 4),
        {
            "automatic_duplicate": 0,
            "cause": "PROVIDER_TERMINAL",
            "permit_claim_after": 1,
            "permit_claim_before": 1,
        },
    ),
    "FABRIC-FBA-PREPARED-TO-FENCED-RESTART": (
        (1, 5),
        {
            "automatic_duplicate": 0,
            "cause": "RESTART_VOLATILE_QUEUE_LOST",
            "permit_claim_after": 0,
            "permit_claim_before": 0,
            "provider_start_calls": 0,
        },
    ),
    "FABRIC-FBA-LINK-RETAINED-TO-FENCED-RESTART": (
        (2, 5),
        {
            "automatic_duplicate": 0,
            "cause": "RESTART_PROVIDER_TOKEN_LOST",
            "permit_claim_after": 1,
            "permit_claim_before": 1,
            "provider_start_calls": 0,
        },
    ),
    "FABRIC-FBA-RETRYABLE-RESTART-BEFORE-EXPIRY": (
        (3, 3),
        {
            "cause": "RESTART_DURABLE_RETRY_LIFETIME_VALID",
            "permit_claim_after": 0,
            "permit_claim_before": 0,
            "provider_start_calls": 0,
            "retry_expires_at_ms": 200000,
            "retry_now_ms": 199999,
            "storage_mutations": 0,
        },
    ),
    "FABRIC-FBA-RETRYABLE-RESTART-AT-EXPIRY": (
        (3, 4),
        {
            "cause": "RESTART_DURABLE_RETRY_LIFETIME_EXPIRED",
            "permit_claim_after": 0,
            "permit_claim_before": 0,
            "provider_start_calls": 0,
            "retry_expires_at_ms": 200000,
            "retry_now_ms": 200000,
        },
    ),
    "FABRIC-FBA-CLOSED-TO-DRAINED": (
        (4, 6),
        {
            "cause": "RUNTIME_DISPATCH_RELEASE",
            "permit_claim_after": 1,
            "permit_claim_before": 1,
            "runtime_terminal_revision": 41,
        },
    ),
    "FABRIC-FBA-FENCED-TO-DRAINED": (
        (5, 6),
        {
            "cause": "RUNTIME_DISPATCH_RELEASE_AFTER_RECONCILE",
            "permit_claim_after": 1,
            "permit_claim_before": 1,
            "runtime_terminal_revision": 41,
        },
    ),
}

REQUIRED_FBA_CU_IDS = {
    f"FABRIC-FBA-{family}-CU-{classification}"
    for family in ("CLOSED", "RESTART-FENCE")
    for classification in ("OLD", "NEW", "THIRD")
}

REQUIRED_STORAGE_NEGATIVE_IDS = {
    "FABRIC-STORE-AUTHORITY-ENDPOINT-SELECTOR-MISMATCH",
    "FABRIC-STORE-AUTHORITY-SCOPE-SELECTOR-UNKNOWN",
    "FABRIC-STORE-AUTHORITY-SERVICE-DIRECTION-TRAFFIC-MISMATCH",
    "FABRIC-STORE-META-UNKNOWN-MIGRATION-STATE",
    "FABRIC-STORE-REGISTRY-UNKNOWN-LINK-KIND",
    "FABRIC-STORE-REGISTRY-UNKNOWN-AVAILABILITY-STATE",
    "FABRIC-STORE-REGISTRY-UNKNOWN-LIFECYCLE",
    "FABRIC-STORE-REGISTRY-PEER-NFL1-V2",
    "FABRIC-STORE-POLICY-UNKNOWN-FAMILY",
    "FABRIC-STORE-POLICY-UNKNOWN-DIRECTION",
    "FABRIC-STORE-POLICY-UNKNOWN-SCOPE-SELECTOR",
    "FABRIC-STORE-POLICY-UNKNOWN-AUTHORITY-MODE",
    "FABRIC-STORE-AUTHORITY-UNKNOWN-STATE",
    "FABRIC-STORE-ATTEMPT-UNKNOWN-STATE",
    "FABRIC-STORE-TRIGGER-UNKNOWN-KIND",
    "FABRIC-STORE-TRIGGER-UNKNOWN-AUTHORITY-STATE",
}

STORAGE_ENUM_NEGATIVE_IDS = {
    "FABRIC-STORE-META-UNKNOWN-MIGRATION-STATE",
    "FABRIC-STORE-REGISTRY-UNKNOWN-LINK-KIND",
    "FABRIC-STORE-REGISTRY-UNKNOWN-AVAILABILITY-STATE",
    "FABRIC-STORE-REGISTRY-UNKNOWN-LIFECYCLE",
    "FABRIC-STORE-REGISTRY-PEER-NFL1-V2",
    "FABRIC-STORE-POLICY-UNKNOWN-FAMILY",
    "FABRIC-STORE-POLICY-UNKNOWN-DIRECTION",
    "FABRIC-STORE-POLICY-UNKNOWN-SCOPE-SELECTOR",
    "FABRIC-STORE-POLICY-UNKNOWN-AUTHORITY-MODE",
    "FABRIC-STORE-AUTHORITY-SCOPE-SELECTOR-UNKNOWN",
    "FABRIC-STORE-AUTHORITY-UNKNOWN-STATE",
    "FABRIC-STORE-ATTEMPT-UNKNOWN-STATE",
    "FABRIC-STORE-TRIGGER-UNKNOWN-KIND",
    "FABRIC-STORE-TRIGGER-UNKNOWN-AUTHORITY-STATE",
}

REQUIRED_FRESH_IDS = {
    "FABRIC-FRESH-COMMIT-OK-REOPEN-EXISTING",
    "FABRIC-EXISTING-WITHOUT-META",
    "FABRIC-EXISTING-DUPLICATE-KEY",
    "FABRIC-EXISTING-OUT-OF-ORDER",
    "FABRIC-EXISTING-COUNT-OVERFLOW",
}

FRESH_CASES: dict[str, dict[str, Any]] = {
    "FABRIC-FRESH-READ-ONLY-ZERO-ROWS": {
        "phase": "READ_ONLY_SCAN",
        "result": "ROLLBACK_OK_THEN_OPEN_READ_WRITE",
    },
    "FABRIC-FRESH-READ-WRITE-ZERO-ROWS": {
        "phase": "READ_WRITE_RESCAN",
        "result": "PUT_CANONICAL_FBM1_REVISION_1_FULL",
    },
    "FABRIC-FRESH-READ-WRITE-RACE": {
        "phase": "READ_WRITE_RESCAN",
        "result": "CORRUPT_MUTATION_ZERO",
    },
    "FABRIC-FRESH-COMMIT-OK-REOPEN-EXISTING": {
        "phase": "REOPEN_READ_ONLY_EXISTING_SCAN",
        "commit_result": "OK",
        "classification": "EXISTING",
        "registry_publish": 1,
    },
    "FABRIC-EXISTING-WITHOUT-META": {
        "phase": "READ_ONLY_EXISTING_SCAN",
        "classification": "CORRUPT",
        "registry_publish": 0,
    },
    "FABRIC-EXISTING-DUPLICATE-KEY": {
        "phase": "READ_ONLY_EXISTING_SCAN",
        "classification": "CORRUPT",
        "registry_publish": 0,
    },
    "FABRIC-EXISTING-OUT-OF-ORDER": {
        "phase": "READ_ONLY_EXISTING_SCAN",
        "classification": "CORRUPT",
        "registry_publish": 0,
    },
    "FABRIC-EXISTING-COUNT-OVERFLOW": {
        "phase": "READ_ONLY_EXISTING_SCAN",
        "overflow_prefix": "FBP1",
        "observed_count": 65,
        "maximum_count": 64,
        "classification": "CORRUPT",
        "registry_publish": 0,
    },
    "FABRIC-FRESH-COMMIT-UNKNOWN-ABSENT": {
        "phase": "REOPEN_READ_CLASSIFY",
        "classification": "ABSENT",
        "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
    },
    "FABRIC-FRESH-COMMIT-UNKNOWN-NEW": {
        "phase": "REOPEN_READ_CLASSIFY",
        "classification": "NEW",
        "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
    },
    "FABRIC-FRESH-COMMIT-UNKNOWN-THIRD": {
        "phase": "REOPEN_READ_CLASSIFY",
        "classification": "CORRUPT",
        "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
    },
}

REQUIRED_NFL_NEGATIVE_IDS = {
    "FABRIC-NFL1-UNKNOWN-RECEIPT-STAGE",
    "FABRIC-NFL1-UNKNOWN-DISPOSITION",
    "FABRIC-NFL1-UNKNOWN-EFFECT-CERTAINTY",
    "FABRIC-NFL1-UNKNOWN-RETRY-GUIDANCE",
    "FABRIC-NFL1-UNKNOWN-CANCEL-KIND",
    "FABRIC-NFL1-UNKNOWN-FAMILY",
    "FABRIC-NFL1-UNKNOWN-EVIDENCE-TRUST",
    "FABRIC-NFL1-UNKNOWN-DESCRIPTOR-DIGEST-ALGORITHM",
    "FABRIC-NFL1-UNKNOWN-CONTENT-DIGEST-ALGORITHM",
    "FABRIC-NFL1-UNKNOWN-ROUTE-DIGEST-ALGORITHM",
}

NFL1_BOUNDARY_CASES: dict[str, tuple[str, int, str]] = {
    "FABRIC-NFL1-APPLICATION-MIN": ("positive", 587, "ACCEPT"),
    "FABRIC-NFL1-STRUCTURAL-1925-SEMANTIC-REJECT": (
        "negative",
        1925,
        "REJECT_KIND_MATRIX_PAYLOAD_AND_EVIDENCE",
    ),
    "FABRIC-NFL1-STRUCTURAL-LENGTH-1926": (
        "negative",
        1926,
        "REJECT_STRUCTURAL_LENGTH_CEILING",
    ),
    "FABRIC-NFL1-CODEC-BUFFER-2049": (
        "negative",
        2049,
        "REJECT_CODEC_BUFFER_CEILING",
    ),
    "FABRIC-NFL1-STRUCTURAL-LENGTH-586": (
        "negative",
        586,
        "REJECT_STRUCTURAL_LENGTH_FLOOR",
    ),
}

VALUE_BYTES = {
    b"FBM1": 64,
    b"FBR1": 372,
    b"FBP1": 352,
    b"FBC1": 512,
    b"FBA1": 712,
    b"FBT1": 248,
}

KEY_BYTES = {
    b"FBM1": 4,
    b"FBR1": 20,
    b"FBP1": 28,
    b"FBC1": 20,
    b"FBA1": 76,
    b"FBT1": 40,
}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def exact_id_map(
    value: Any,
    expected_ids: tuple[str, ...],
    label: str,
) -> dict[str, dict[str, Any]]:
    require(isinstance(value, list), f"{label}: vectors must be an array")
    expected = set(expected_ids)
    require(
        len(expected_ids) == len(expected),
        f"{label}: internal expected ID inventory has duplicates",
    )
    require(
        len(value) == len(expected_ids),
        f"{label}: exact vector count",
    )
    rows: list[dict[str, Any]] = []
    ids: list[str] = []
    for index, row in enumerate(value):
        require(isinstance(row, dict), f"{label}[{index}]: vector must be an object")
        vector_id = row.get("id")
        require(
            isinstance(vector_id, str),
            f"{label}[{index}]: vector ID must be a string",
        )
        rows.append(row)
        ids.append(vector_id)
    require(len(ids) == len(set(ids)), f"{label}: duplicate vector ID")
    require(set(ids) == expected, f"{label}: unknown/missing vector ID")
    return {row["id"]: row for row in rows}


def be16(value: bytes) -> int:
    return struct.unpack(">H", value)[0]


def be32(value: bytes) -> int:
    return struct.unpack(">I", value)[0]


def be64(value: bytes) -> int:
    return struct.unpack(">Q", value)[0]


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def record_crc_ok(value: bytes) -> bool:
    mutable = bytearray(value)
    stored = be32(mutable[20:24])
    mutable[20:24] = b"\0" * 4
    return crc32c(bytes(mutable)) == stored


def repair_record_crc(value: bytes) -> bytes:
    mutable = bytearray(value)
    mutable[20:24] = b"\0" * 4
    mutable[20:24] = struct.pack(">I", crc32c(bytes(mutable)))
    return bytes(mutable)


def repair_nfl1_crc(value: bytes) -> bytes:
    mutable = bytearray(value)
    mutable[12:16] = b"\0" * 4
    mutable[12:16] = struct.pack(">I", crc32c(bytes(mutable)))
    return bytes(mutable)


def parse_record(key_hex: str, value_hex: str, label: str) -> tuple[bytes, bytes]:
    key = bytes.fromhex(key_hex)
    value = bytes.fromhex(value_hex)
    magic = value[:4]
    require(magic in VALUE_BYTES, f"{label}: unknown magic")
    require(key[:4] == magic, f"{label}: key/value magic")
    require(len(key) == KEY_BYTES[magic], f"{label}: key size")
    require(len(value) == VALUE_BYTES[magic], f"{label}: value size")
    require(be16(value[4:6]) == 1, f"{label}: schema")
    require(be16(value[6:8]) == 24, f"{label}: header size")
    require(be32(value[8:12]) == len(value), f"{label}: total size")
    require(be64(value[12:20]) != 0, f"{label}: zero revision")
    require(record_crc_ok(value), f"{label}: CRC32C")
    if magic == b"FBP1":
        require(key[4:20] == value[24:40], f"{label}: policy key")
        require(
            key[20:28] == value[40:48],
            f"{label}: policy revision key",
        )
        payload = bytearray(value[24:])
        stored = bytes(payload[24:56])
        payload[24:56] = b"\0" * 32
        expected = hashlib.sha256(
            b"NINLIL-FABRIC-POLICY-V1" + bytes(payload)
        ).digest()
        require(stored == expected, f"{label}: policy digest")
        require(be32(value[112:116]) == 2, f"{label}: policy family")
        require(be32(value[116:120]) in (1, 2), f"{label}: policy direction")
        require(be16(value[122:124]) in (1, 2), f"{label}: policy selector")
        require(value[140] in (0, 1), f"{label}: authority mode")
    if magic == b"FBM1":
        require(be16(value[28:30]) == 1, f"{label}: migration state")
    if magic == b"FBR1":
        require(key[4:20] == value[24:40], f"{label}: instance key")
        require(be32(value[40:44]) in (1, 2, 3, 4), f"{label}: link kind")
        require(value[312] in (0, 1), f"{label}: availability state")
        require(value[313] in (1, 2), f"{label}: registry lifecycle")
        require(be16(value[324:326]) == 1, f"{label}: peer NFL1 version")
    if magic == b"FBC1":
        require(key[4:20] == value[24:40], f"{label}: binding key")
        selector = be16(value[82:84])
        state = be32(value[188:192])
        require(selector in (1, 2), f"{label}: FBC selector")
        require(state in (0, 1), f"{label}: FBC state")
        if selector == 2:
            require(value[84:100] == value[100:116], f"{label}: target endpoint")
        if state == 0:
            require(value[188:496] == b"\0" * 308, f"{label}: ABSENT matrix")
        else:
            expected_owner = hashlib.sha256(
                b"NINLIL-FABRIC-OWNER-TUPLE-V1" + value[272:472]
            ).digest()
            require(value[240:272] == expected_owner, f"{label}: owner digest")
    if magic == b"FBA1":
        require(key[4:20] == value[24:40], f"{label}: transaction key")
        require(key[20:36] == value[40:56], f"{label}: attempt key")
        require(key[36:40] == value[56:60], f"{label}: kind key")
        require(key[40:44] == value[60:64], f"{label}: slot key")
        require(key[44:76] == value[68:100], f"{label}: digest key")
        require(value[620:636] != b"\0" * 16, f"{label}: retry epoch")
        require(be64(value[636:644]) != 0, f"{label}: retry expiry")
        dispatch = hashlib.sha256(
            b"NINLIL-FABRIC-LOCAL-DISPATCH-V1" + key
        ).digest()
        require(value[644:676] == dispatch, f"{label}: dispatch digest")
        state = be32(value[64:68])
        claim = be32(value[708:712])
        require(1 <= state <= 6, f"{label}: FBA state")
        require(value[684:700] != b"\0" * 16, f"{label}: permit ID")
        require(be64(value[700:708]) != 0, f"{label}: permit expiry")
        require(claim in (0, 1), f"{label}: permit claim state")
        require(
            state != 2 or claim == 1,
            f"{label}: LINK_RETAINED keeps CLAIMED",
        )
        require(
            state != 3 or claim == 0,
            f"{label}: RETRYABLE keeps CLEAR",
        )
    if magic == b"FBT1":
        require(
            key[4:20] == value[24:40],
            f"{label}: trigger transaction key",
        )
        require(
            key[20:36] == value[40:56],
            f"{label}: trigger attempt key",
        )
        require(
            key[36:40] == value[56:60],
            f"{label}: trigger kind key",
        )
        require(be32(value[56:60]) in (1, 4), f"{label}: trigger kind")
        require(be32(value[60:64]) in (0, 1), f"{label}: trigger authority")
    return key, value


def nfl1_closed_enum_error(packet: bytes) -> str | None:
    if len(packet) < 570:
        return None
    if be16(packet[4:6]) != 1:
        return "REJECT_UNKNOWN_VERSION"
    kind = be32(packet[16:20])
    if kind not in (1, 2, 3, 4, 5, 6):
        return "REJECT_UNKNOWN_MESSAGE_KIND"
    if be16(packet[308:310]) != 1:
        return "REJECT_UNKNOWN_DESCRIPTOR_DIGEST_ALGORITHM"
    if be32(packet[346:350]) not in {
        1,
        2,
        3,
        4,
        5,
        6,
        0x80000001,
    }:
        return "REJECT_UNKNOWN_FAMILY"
    if be16(packet[350:352]) != 1:
        return "REJECT_UNKNOWN_CONTENT_DIGEST_ALGORITHM"
    if be16(packet[508:510]) != 1:
        return "REJECT_UNKNOWN_ROUTE_DIGEST_ALGORITHM"
    if kind == 2:
        if be32(packet[428:432]) not in (1, 2, 3, 4):
            return "REJECT_UNKNOWN_RECEIPT_STAGE"
        if be32(packet[480:484]) not in (0, 1, 2):
            return "REJECT_UNKNOWN_EVIDENCE_TIME_TRUST"
    if kind == 3:
        if be32(packet[432:436]) not in range(1, 11):
            return "REJECT_UNKNOWN_DISPOSITION"
        if be32(packet[436:440]) not in (1, 2):
            return "REJECT_UNKNOWN_EFFECT_CERTAINTY"
        if be32(packet[440:444]) not in (0, 1, 2, 3):
            return "REJECT_UNKNOWN_RETRY_GUIDANCE"
    if kind == 6 and be32(packet[444:448]) not in (1, 2, 3):
        return "REJECT_UNKNOWN_CANCEL_KIND"
    return None


def nfl1_boundary_result(packet: bytes) -> str:
    if len(packet) > 2048:
        return "REJECT_CODEC_BUFFER_CEILING"
    if len(packet) < 587:
        return "REJECT_STRUCTURAL_LENGTH_FLOOR"
    if len(packet) > 1925:
        return "REJECT_STRUCTURAL_LENGTH_CEILING"
    if (
        packet[:4] != b"NFL1"
        or be16(packet[4:6]) != 1
        or be16(packet[6:8]) != 584
        or be32(packet[8:12]) != len(packet)
    ):
        return "REJECT_NFL1_FRAMING"
    variable_bytes = (
        be16(packet[570:572])
        + be16(packet[572:574])
        + be16(packet[574:576])
        + be32(packet[576:580])
        + be32(packet[580:584])
    )
    if 584 + variable_bytes != len(packet):
        return "REJECT_NFL1_FRAMING"
    mutable = bytearray(packet)
    stored_crc = be32(mutable[12:16])
    mutable[12:16] = b"\0" * 4
    if crc32c(bytes(mutable)) != stored_crc:
        return "REJECT_NFL1_FRAMING"
    if (
        be32(packet[16:20]) == 1
        and be32(packet[576:580]) > 0
        and be32(packet[580:584]) > 0
    ):
        return "REJECT_KIND_MATRIX_PAYLOAD_AND_EVIDENCE"
    return "ACCEPT"


def project_durable_selection(
    snapshot: dict[str, Any],
    *,
    query: dict[str, Any],
    active_attempts: list[dict[str, Any]],
    label: str,
) -> dict[str, Any]:
    decoded: dict[bytes, list[tuple[bytes, bytes]]] = {
        magic: [] for magic in VALUE_BYTES
    }
    for row_name, raw in snapshot["durable_rows"].items():
        key, value = parse_record(
            raw["key_hex"],
            raw["value_hex"],
            f"{label}:{row_name}",
        )
        decoded[value[:4]].append((key, value))

    require(len(decoded[b"FBM1"]) == 1, f"{label}: exact FBM1")
    meta_value = decoded[b"FBM1"][0][1]
    meta = {
        "record_revision": be64(meta_value[12:20]),
        "outer_availability_epoch": be64(meta_value[48:56]),
        "outer_available": be32(meta_value[56:60]),
    }

    registry: list[dict[str, Any]] = []
    for key, value in decoded[b"FBR1"]:
        require(key[4:20] == value[24:40], f"{label}: FBR identity")
        registry.append(
            {
                "instance_id_hex": value[24:40].hex(),
                "record_revision": be64(value[12:20]),
                "lifecycle": {1: "ACTIVE", 2: "DRAINING"}[value[313]],
                "direction_mask": be32(value[44:48]),
                "link_kind": {
                    1: "LOOPBACK",
                    2: "WIFI",
                    3: "USB",
                    4: "RF",
                }[be32(value[40:44])],
                "capability_flags": be32(value[48:52]),
                "maximum_packet_bytes": be32(value[272:276]),
                "maximum_transfer_bytes": be32(value[276:280]),
                "latency_class": be16(value[280:282]),
                "cost_class": be16(value[282:284]),
                "reservation_capacity": be16(value[284:286]),
                "security_capability_flags": be32(value[108:112]),
                "peer_nfl1_version": be16(value[324:326]),
                "peer_fabric_capability_flags": be32(value[328:332]),
                "authenticated_peer_runtime_id_hex": value[208:224].hex(),
                "attachment_authority_id_hex": value[224:240].hex(),
                "attachment_binding_digest_hex": value[240:272].hex(),
                "attestation_epoch": be64(value[144:152]),
                "attestation_clock_epoch_id_hex": value[152:168].hex(),
                "attestation_expires_at_ms": be64(value[168:176]),
                "availability_epoch": be64(value[288:296]),
                "availability_clock_epoch_id_hex": value[296:312].hex(),
                "availability_state": value[312],
                "availability_expires_at_ms": be64(value[316:324]),
            }
        )

    policy_versions: dict[str, list[tuple[bytes, bytes]]] = {}
    for key, value in decoded[b"FBP1"]:
        policy_id = value[24:40].hex()
        require(
            key[4:20] == value[24:40]
            and be64(key[20:28]) == be64(value[40:48]),
            f"{label}: FBP identity",
        )
        policy_versions.setdefault(policy_id, []).append((key, value))
    policies: list[dict[str, Any]] = []
    for policy_id, versions in policy_versions.items():
        versions.sort(key=lambda item: be64(item[1][40:48]))
        revision_chain = [be64(item[1][40:48]) for item in versions]
        require(
            len(revision_chain) == len(set(revision_chain)),
            f"{label}: duplicate FBP revision",
        )
        value = versions[-1][1]
        candidate_count = be16(value[152:154])
        require(candidate_count <= 8, f"{label}: FBP candidate count")
        candidates = []
        for index in range(candidate_count):
            offset = 160 + index * 24
            candidates.append(
                {
                    "instance_id_hex": value[offset : offset + 16].hex(),
                    "rank": be16(value[offset + 16 : offset + 18]),
                    "reservation_units": be16(
                        value[offset + 20 : offset + 22]
                    ),
                }
            )
        policies.append(
            {
                "policy_id_hex": policy_id,
                "revision": be64(value[40:48]),
                "revision_chain": revision_chain,
                "canonical_digest_hex": value[48:80].hex(),
                "service_identity_digest_hex": value[80:112].hex(),
                "family": be32(value[112:116]),
                "direction": be32(value[116:120]),
                "traffic_class": be16(value[120:122]),
                "scope_selector": {
                    1: "SOURCE_RUNTIME",
                    2: "TARGET_RUNTIME",
                }[be16(value[122:124])],
                "required_capability_flags": be32(value[124:128]),
                "required_security_flags": be32(value[128:132]),
                "maximum_latency_class": be16(value[132:134]),
                "maximum_cost_class": be16(value[134:136]),
                "minimum_packet_bytes": be32(value[136:140]),
                "authority_mode": {
                    0: "ABSENT_ALLOWED",
                    1: "BOUND_REQUIRED",
                }[value[140]],
                "deadline_guard_ms": be64(value[144:152]),
                "candidates": candidates,
            }
        )

    authorities: list[dict[str, Any]] = []
    for key, value in decoded[b"FBC1"]:
        require(key[4:20] == value[24:40], f"{label}: FBC identity")
        state = be32(value[188:192])
        authorities.append(
            {
                "binding_id_hex": value[24:40].hex(),
                "service_identity_digest_hex": value[40:72].hex(),
                "family": be32(value[72:76]),
                "direction": be32(value[76:80]),
                "traffic_class": be16(value[80:82]),
                "scope_selector": {
                    1: "SOURCE_RUNTIME",
                    2: "TARGET_RUNTIME",
                }[be16(value[82:84])],
                "endpoint_runtime_id_hex": value[84:100].hex(),
                "target_runtime_id_hex": value[100:116].hex(),
                "target_application_id_hex": value[116:132].hex(),
                "policy_id_hex": value[132:148].hex(),
                "policy_revision": be64(value[148:156]),
                "policy_digest_hex": value[156:188].hex(),
                "authority_state": "ABSENT" if state == 0 else "BOUND",
                "authority_clock_epoch_id_hex": value[472:488].hex(),
                "lease_expires_at_ms": be64(value[488:496]),
            }
        )

    return {
        "meta": meta,
        "query": copy.deepcopy(query),
        "policies": policies,
        "registry": registry,
        "authorities": authorities,
        "active_attempts": copy.deepcopy(active_attempts),
    }


def normalized_selection_inputs(snapshot: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(
        {
            name: snapshot[name]
            for name in (
                "meta",
                "query",
                "policies",
                "registry",
                "authorities",
                "active_attempts",
            )
        }
    )
    for group in ("policies", "registry", "authorities"):
        for row in normalized[group]:
            row.pop("source_record_id", None)
    normalized["policies"].sort(key=lambda row: row["policy_id_hex"])
    normalized["registry"].sort(key=lambda row: row["instance_id_hex"])
    normalized["authorities"].sort(key=lambda row: row["binding_id_hex"])
    normalized["meta"].pop("source_record_id", None)
    return normalized


def selection_decision(snapshot: dict[str, Any]) -> tuple[str | None, str | None]:
    query = snapshot["query"]
    if snapshot["meta"]["outer_available"] != 1:
        return None, "META_OUTER_UNAVAILABLE"

    for policy in snapshot["policies"]:
        chain = policy["revision_chain"]
        if (
            not chain
            or chain[-1] != policy["revision"]
            or any(b != a + 1 for a, b in zip(chain, chain[1:]))
        ):
            return None, "POLICY_REVISION_GAP"
    policies = [
        row
        for row in snapshot["policies"]
        if (
            row["service_identity_digest_hex"]
            == query["service_identity_digest_hex"]
            and row["family"] == query["family"]
            and row["direction"] == query["direction"]
            and row["traffic_class"] == query["traffic_class"]
        )
    ]
    if not policies:
        return None, "POLICY_NO_MATCH"
    if len(policies) != 1:
        return None, "POLICY_AMBIGUOUS"
    policy = policies[0]
    endpoint = query[
        "source_runtime_id_hex"
        if policy["scope_selector"] == "SOURCE_RUNTIME"
        else "target_runtime_id_hex"
    ]

    eligible: list[tuple[tuple[Any, ...], str]] = []
    first_rejection = None
    for candidate in policy["candidates"]:
        instance = candidate["instance_id_hex"]
        registries = [
            row for row in snapshot["registry"] if row["instance_id_hex"] == instance
        ]
        if len(registries) != 1:
            reason = (
                "REGISTRY_JOIN_MISSING"
                if not registries
                else "REGISTRY_JOIN_AMBIGUOUS"
            )
            first_rejection = first_rejection or reason
            continue
        registry = registries[0]
        authorities = [
            row
            for row in snapshot["authorities"]
            if (
                row["service_identity_digest_hex"]
                == query["service_identity_digest_hex"]
                and row["family"] == query["family"]
                and row["direction"] == query["direction"]
                and row["traffic_class"] == query["traffic_class"]
                and row["scope_selector"] == policy["scope_selector"]
                and row["endpoint_runtime_id_hex"] == endpoint
                and row["target_runtime_id_hex"] == query["target_runtime_id_hex"]
                and row["target_application_id_hex"]
                == query["target_application_id_hex"]
                and row["policy_id_hex"] == policy["policy_id_hex"]
                and row["policy_revision"] == policy["revision"]
                and row["policy_digest_hex"] == policy["canonical_digest_hex"]
            )
        ]
        reasons: list[str] = []
        if len(authorities) != 1:
            reasons.append(
                "AUTHORITY_JOIN_MISSING"
                if not authorities
                else "AUTHORITY_JOIN_AMBIGUOUS"
            )
            authority = None
        else:
            authority = authorities[0]

        # Hard-filter chain after join (Normative order; primary = first).
        if registry["lifecycle"] != "ACTIVE":
            reasons.append("LIFECYCLE_DRAINING")
        if registry["direction_mask"] & 1 == 0:
            reasons.append("DIRECTION_MISMATCH")
        if query["packet_bytes"] < NFL1_STRUCTURAL_MIN:
            reasons.append("STRUCTURAL_LENGTH_FLOOR")
        if query["packet_bytes"] > NFL1_STRUCTURAL_MAX:
            reasons.append("STRUCTURAL_LENGTH_CEILING")
        if query["packet_bytes"] < policy["minimum_packet_bytes"]:
            reasons.append("PACKET_MINIMUM")
        if query["packet_bytes"] > registry["maximum_packet_bytes"]:
            reasons.append("PACKET_MTU")
        if query["transfer_bytes"] > registry["maximum_transfer_bytes"]:
            reasons.append("TRANSFER_MTU")
        if registry["latency_class"] > policy["maximum_latency_class"]:
            reasons.append("LATENCY_CLASS")
        if registry["cost_class"] > policy["maximum_cost_class"]:
            reasons.append("COST_CLASS")
        if query["deadline_ms"] - query["now_ms"] < policy["deadline_guard_ms"]:
            reasons.append("DEADLINE_GUARD")
        if (
            query["deadline_clock_epoch_id_hex"]
            != query["admission_clock_epoch_id_hex"]
            or query["deadline_clock_epoch_id_hex"]
            != query["availability_clock_epoch_id_hex"]
        ):
            reasons.append("RETRY_LIFETIME_CLOCK_EPOCH")
        used = sum(
            row["reservation_units"]
            for row in snapshot["active_attempts"]
            if row["instance_id_hex"] == instance
            and row["state"] in ("PREPARED", "LINK_RETAINED")
        )
        if used + candidate["reservation_units"] > registry["reservation_capacity"]:
            reasons.append("RESERVATION_CAPACITY")
        caps = policy["required_capability_flags"] | query[
            "required_capability_flags"
        ]
        if registry["capability_flags"] & caps != caps:
            reasons.append("CAPABILITY_MISSING")
        if query["requires_sleep_compatible"] and registry["capability_flags"] & 1 == 0:
            reasons.append("ENERGY_SLEEP_CAPABILITY_MISSING")
        security = policy["required_security_flags"] | query[
            "required_security_flags"
        ]
        if registry["security_capability_flags"] & security != security:
            reasons.append("SECURITY_MISSING")
        if query["requires_custody"] and (
            registry["link_kind"] == "WIFI"
            or registry["capability_flags"] & 0x20 == 0
        ):
            reasons.append("CUSTODY_MISSING")
        if query["requires_evidence"] and registry["capability_flags"] & 0x40 == 0:
            reasons.append("EVIDENCE_MISSING")
        if (
            registry["peer_nfl1_version"] != 1
            or registry["peer_fabric_capability_flags"] & 1 == 0
        ):
            reasons.append("PEER_NFL1")
        if (
            registry["authenticated_peer_runtime_id_hex"]
            != query["authenticated_peer_runtime_id_hex"]
        ):
            reasons.append("AUTHENTICATED_PEER_MISMATCH")
        if (
            registry["attachment_authority_id_hex"]
            != query["attachment_authority_id_hex"]
        ):
            reasons.append("ATTACHMENT_AUTHORITY_MISMATCH")
        if (
            registry["attachment_binding_digest_hex"]
            != query["attachment_binding_digest_hex"]
        ):
            reasons.append("ATTACHMENT_BINDING_MISMATCH")
        if (
            registry["attestation_clock_epoch_id_hex"]
            != query["attestation_clock_epoch_id_hex"]
        ):
            reasons.append("ATTESTATION_EPOCH")
        elif query["now_ms"] >= registry["attestation_expires_at_ms"]:
            reasons.append("ATTESTATION_EXPIRED")
        if (
            registry["availability_clock_epoch_id_hex"]
            != query["availability_clock_epoch_id_hex"]
        ):
            reasons.append("AVAILABILITY_EPOCH")
        elif registry["availability_state"] != 1:
            reasons.append("AVAILABILITY_STATE")
        elif query["now_ms"] >= registry["availability_expires_at_ms"]:
            reasons.append("AVAILABILITY_EXPIRED")
        if authority is not None:
            if (
                policy["authority_mode"] == "BOUND_REQUIRED"
                and authority["authority_state"] != "BOUND"
            ):
                reasons.append("BOUND_REQUIRED_ABSENT")
            elif authority["authority_state"] == "BOUND":
                if (
                    authority["authority_clock_epoch_id_hex"]
                    != query["authority_clock_epoch_id_hex"]
                ):
                    reasons.append("AUTHORITY_CLOCK_EPOCH")
                elif query["now_ms"] >= authority["lease_expires_at_ms"]:
                    reasons.append("AUTHORITY_LEASE_EXPIRED")
        if registry["link_kind"] == "RF":
            if not query["rf_permit_valid"]:
                reasons.append("RF_PERMIT")
            if not query["rf_mapping_accepted"]:
                reasons.append("RF_MAPPING_UNSUPPORTED")
        if reasons:
            first_rejection = first_rejection or reasons[0]
        else:
            eligible.append(
                (
                    (
                        candidate["rank"],
                        registry["latency_class"],
                        registry["cost_class"],
                        instance,
                    ),
                    instance,
                )
            )
    eligible.sort()
    return (eligible[0][1] if eligible else None), first_rejection


def apply_declared_mutation(base: dict[str, Any], mutation: dict[str, Any]) -> None:
    cursor: Any = base
    for part in mutation["path"]:
        cursor = cursor[part]
    operation = mutation["operation"]
    if operation == "replace":
        require(cursor == mutation["old"], "selection mutation old mismatch")
        parent: Any = base
        for part in mutation["path"][:-1]:
            parent = parent[part]
        parent[mutation["path"][-1]] = mutation["new"]
    elif operation == "append":
        cursor.append(mutation["new"])
    elif operation == "remove":
        old = copy.deepcopy(mutation["old"])
        if isinstance(old, dict):
            old.pop("source_record_id", None)
        match = None
        for item in cursor:
            candidate = copy.deepcopy(item)
            if isinstance(candidate, dict):
                candidate.pop("source_record_id", None)
            if candidate == old:
                match = item
                break
        require(match is not None, "selection remove old mismatch")
        cursor.remove(match)
    else:
        raise GateError("selection mutation operation")



def assert_selection_semantics(vector_id: str, row: dict[str, Any]) -> None:
    """Fail closed if row ID does not carry the independent semantic authority."""
    expected = SELECTION_SEMANTICS.get(vector_id)
    require(expected is not None, f"{vector_id}: missing SELECTION_SEMANTICS")
    model = row["model"]
    inputs = row["inputs"]
    require(
        model.get("primary_rejection") == expected["primary_rejection"],
        f"{vector_id}: primary_rejection semantic",
    )
    require(
        model.get("resolution") == expected["resolution"],
        f"{vector_id}: resolution semantic",
    )
    require(
        model.get("selected_instance_id_hex")
        == expected["selected_instance_id_hex"],
        f"{vector_id}: selected instance semantic",
    )
    query = inputs["query"]
    require(query["packet_bytes"] == expected["packet_bytes"], f"{vector_id}: packet_bytes")
    require(
        query["transfer_bytes"] == expected["transfer_bytes"],
        f"{vector_id}: transfer_bytes",
    )
    require(
        inputs["meta"]["outer_available"] == expected["outer_available"],
        f"{vector_id}: outer_available",
    )
    require(
        len(inputs["authorities"]) == expected["authority_count"],
        f"{vector_id}: authority_count",
    )
    require(
        len(inputs["registry"]) == expected["registry_count"],
        f"{vector_id}: registry_count",
    )
    require(
        len(inputs["policies"]) == expected["policy_count"],
        f"{vector_id}: policy_count",
    )
    if expected["minimum_packet_bytes"] is not None:
        require(
            inputs["policies"][0]["minimum_packet_bytes"]
            == expected["minimum_packet_bytes"],
            f"{vector_id}: minimum_packet_bytes",
        )
    if expected["maximum_packet_bytes"] is not None:
        require(
            inputs["registry"][0]["maximum_packet_bytes"]
            == expected["maximum_packet_bytes"],
            f"{vector_id}: maximum_packet_bytes",
        )
    if expected["lifecycle"] is not None:
        require(
            inputs["registry"][0]["lifecycle"] == expected["lifecycle"],
            f"{vector_id}: lifecycle",
        )
    if expected["direction_mask"] is not None:
        require(
            inputs["registry"][0]["direction_mask"] == expected["direction_mask"],
            f"{vector_id}: direction_mask",
        )
    if expected.get("filter_index") is not None:
        require(
            HARD_FILTER_ORDER[expected["filter_index"]]
            == expected["primary_rejection"],
            f"{vector_id}: filter_index order",
        )
        require(
            model.get("primary_rejection")
            == HARD_FILTER_ORDER[expected["filter_index"]],
            f"{vector_id}: primary vs filter_index",
        )
    if "rejection_reasons" in expected:
        reasons = (
            model["evaluated"][0]["rejection_reasons"]
            if model.get("evaluated")
            else []
        )
        require(
            reasons == expected["rejection_reasons"],
            f"{vector_id}: rejection_reasons order",
        )
        if expected.get("filter_index") is not None and reasons:
            require(
                reasons[0] == expected["primary_rejection"],
                f"{vector_id}: primary is first reason",
            )
    if expected.get("mutation_op") == "replace":
        mut = row.get("mutation") or {}
        require(mut.get("operation") == "replace", f"{vector_id}: mutation op")
        require(mut.get("path") == expected["mutation_path"], f"{vector_id}: mutation path")
        require(mut.get("new") == expected["mutation_new"], f"{vector_id}: mutation new")
    elif expected.get("mutation_op") in ("append", "remove"):
        mut = row.get("mutation") or {}
        require(
            mut.get("operation") == expected["mutation_op"],
            f"{vector_id}: mutation op",
        )
        require(mut.get("path") == expected["mutation_path"], f"{vector_id}: mutation path")
    if "scope_selector" in expected:
        require(
            inputs["policies"][0]["scope_selector"] == expected["scope_selector"],
            f"{vector_id}: scope_selector",
        )
    if "authority_mode" in expected:
        require(
            inputs["policies"][0]["authority_mode"] == expected["authority_mode"],
            f"{vector_id}: authority_mode",
        )
    if "authority_state" in expected:
        require(
            inputs["authorities"][0]["authority_state"] == expected["authority_state"],
            f"{vector_id}: authority_state",
        )
    if "link_kind" in expected:
        require(
            inputs["registry"][0]["link_kind"] == expected["link_kind"],
            f"{vector_id}: link_kind",
        )
    if "rf_mapping_accepted" in expected:
        require(
            query["rf_mapping_accepted"] == expected["rf_mapping_accepted"],
            f"{vector_id}: rf_mapping_accepted",
        )
    if "rf_permit_valid" in expected:
        require(
            query["rf_permit_valid"] == expected["rf_permit_valid"],
            f"{vector_id}: rf_permit_valid",
        )
    if "latency_class" in expected:
        require(
            inputs["registry"][0]["latency_class"] == expected["latency_class"],
            f"{vector_id}: latency_class",
        )
    if "cost_class" in expected:
        require(
            inputs["registry"][0]["cost_class"] == expected["cost_class"],
            f"{vector_id}: cost_class",
        )
    if "security_capability_flags" in expected:
        require(
            inputs["registry"][0]["security_capability_flags"]
            == expected["security_capability_flags"],
            f"{vector_id}: security_capability_flags",
        )
    if "authority_binding_ids" in expected:
        bindings = sorted(a["binding_id_hex"] for a in inputs["authorities"])
        require(
            bindings == expected["authority_binding_ids"],
            f"{vector_id}: authority binding identity set",
        )
        require(
            len(set(bindings)) == expected["authority_count"],
            f"{vector_id}: distinct authority bindings",
        )
        policy_ids = [a["policy_id_hex"] for a in inputs["authorities"]]
        require(
            len(set(policy_ids)) == 1,
            f"{vector_id}: ambiguous authorities share policy identity",
        )
    # Structural/policy boundary pins for dedicated cases.
    if vector_id == "FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR":
        require(query["packet_bytes"] == 586, f"{vector_id}: floor boundary 586")
        require(
            query["packet_bytes"] < NFL1_STRUCTURAL_MIN,
            f"{vector_id}: below structural min",
        )
    if vector_id == "FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING":
        require(query["packet_bytes"] == 1926, f"{vector_id}: ceiling boundary 1926")
        require(
            query["packet_bytes"] > NFL1_STRUCTURAL_MAX,
            f"{vector_id}: above structural max",
        )
    if vector_id == "FABRIC-SELECT-PACKET-MINIMUM":
        require(query["packet_bytes"] == 587, f"{vector_id}: structural-legal packet")
        require(
            inputs["policies"][0]["minimum_packet_bytes"] == 600,
            f"{vector_id}: policy min 600",
        )
        require(
            query["packet_bytes"] >= NFL1_STRUCTURAL_MIN,
            f"{vector_id}: not structural floor",
        )



def validate_python(document: dict[str, Any]) -> None:
    constants = document["constants"]
    entries = 1 + 16 + 64 + 64 + 64 + 64
    key_value = (
        4 + 64
        + 16 * (20 + 372)
        + 64 * (28 + 352)
        + 64 * (20 + 512)
        + 64 * (76 + 712)
        + 64 * (40 + 248)
    )
    require(entries == constants["durable_entries_max"], "entry budget")
    require(
        constants["fabric_workspace_bytes"] == 198656,
        "workspace authority 198656",
    )
    require(
        constants["fabric_attempt_region_bytes"] == 52224
        and constants["fabric_attempt_slot_bytes"] == 816
        and constants["fabric_attempt_region_bytes"]
        == 64 * constants["fabric_attempt_slot_bytes"],
        "attempt region authority 64 x 816",
    )
    require(
        constants["fba1_payload_bytes"] == 688
        and constants["fba1_value_bytes"] == 712,
        "FBA1 size authority 688/712",
    )
    require(key_value == constants["durable_key_value_bytes_max"], "byte budget")
    require(
        key_value + entries * 16 == constants["durable_storage_cu_bytes_max"],
        "CU budget",
    )
    require(
        constants["full_staging_storage_cu_bytes_required"]
        == 2 * constants["durable_storage_cu_bytes_max"],
        "staging CU budget",
    )
    require(
        constants["durable_storage_cu_bytes_max"] == FABRIC_COMMITTED_CU_BYTES,
        "committed CU authority 137940",
    )
    require(
        constants["full_staging_storage_cu_bytes_required"]
        == FABRIC_FULL_STAGING_CU_BYTES,
        "FULL staging CU authority 275880",
    )
    require(
        constants["durable_storage_cu_bytes_max"] not in FABRIC_OBSOLETE_CU_BYTES
        and constants["full_staging_storage_cu_bytes_required"]
        not in FABRIC_OBSOLETE_CU_BYTES,
        "obsolete CU totals rejected",
    )
    docs06 = (ROOT / "docs/06-versioning-and-compatibility.md").read_text(
        encoding="utf-8"
    )
    require(
        "137,940" in docs06 and "275,880" in docs06,
        "docs/06 must publish exact CU totals",
    )
    require(
        "134,612" not in docs06
        and "136,148" not in docs06
        and "269,224" not in docs06
        and "272,296" not in docs06,
        "docs/06 must not publish obsolete CU totals",
    )

    for row in document["nfl1_positive_vectors"]:
        packet = bytes.fromhex(row["encoded_hex"])
        require(len(packet) == row["encoded_length"], f"{row['id']}: length")
        require(
            hashlib.sha256(packet).hexdigest() == row["sha256_hex"],
            f"{row['id']}: sha",
        )
        mutable = bytearray(packet)
        stored = be32(mutable[12:16])
        mutable[12:16] = b"\0" * 4
        require(crc32c(bytes(mutable)) == stored, f"{row['id']}: CRC")
        require(
            nfl1_closed_enum_error(packet) is None,
            f"{row['id']}: positive closed enum",
        )
    for row in document["nfl1_negative_vectors"]:
        packet = bytes.fromhex(row["encoded_hex"])
        require(len(packet) == row["encoded_length"], f"{row['id']}: length")
        require(
            hashlib.sha256(packet).hexdigest() == row["sha256_hex"],
            f"{row['id']}: sha",
        )
    positive_nfl1 = {
        row["id"]: row for row in document["nfl1_positive_vectors"]
    }
    negative_nfl1 = {
        row["id"]: row for row in document["nfl1_negative_vectors"]
    }
    require(
        len(positive_nfl1) == len(document["nfl1_positive_vectors"]),
        "duplicate NFL1 positive vector ID",
    )
    require(
        len(negative_nfl1) == len(document["nfl1_negative_vectors"]),
        "duplicate NFL1 negative vector ID",
    )
    for vector_id, (collection, expected_length, expected) in (
        NFL1_BOUNDARY_CASES.items()
    ):
        rows = (
            positive_nfl1 if collection == "positive" else negative_nfl1
        )
        require(
            vector_id in rows,
            f"{vector_id}: missing NFL1 boundary vector",
        )
        row = rows[vector_id]
        packet = bytes.fromhex(row["encoded_hex"])
        require(
            len(packet) == expected_length,
            f"{vector_id}: exact NFL1 boundary length",
        )
        require(
            row.get("expected", "ACCEPT") == expected,
            f"{vector_id}: exact NFL1 boundary expectation",
        )
        require(
            nfl1_boundary_result(packet) == expected,
            f"{vector_id}: independent NFL1 boundary classification",
        )

    records = {row["id"]: row for row in document["storage_records"]}
    for row in records.values():
        key, value = parse_record(row["key_hex"], row["value_hex"], row["id"])
        require(len(key) == row["key_bytes"], f"{row['id']}: key size fact")
        require(len(value) == row["value_bytes"], f"{row['id']}: value size fact")
        require(
            hashlib.sha256(key + value).hexdigest() == row["sha256_hex"],
            f"{row['id']}: record SHA",
        )

    target = bytes.fromhex(
        records["FABRIC-STORE-AUTHORITY-TARGET-RUNTIME"]["value_hex"]
    )
    source = bytes.fromhex(
        records["FABRIC-STORE-AUTHORITY-SOURCE-RUNTIME"]["value_hex"]
    )
    absent = bytes.fromhex(records["FABRIC-STORE-AUTHORITY-ABSENT"]["value_hex"])
    require(be16(target[82:84]) == 2, "TARGET selector")
    require(target[84:100] == target[100:116], "TARGET endpoint")
    require(be16(source[82:84]) == 1, "SOURCE selector")
    require(
        source[84:100]
        == bytes.fromhex(records["FABRIC-STORE-AUTHORITY-SOURCE-RUNTIME"]["facts"][
            "endpoint_runtime_id_hex"
        ]),
        "SOURCE endpoint",
    )
    require(be32(absent[188:192]) == 0, "ABSENT state")
    require(absent[188:496] == b"\0" * 308, "ABSENT zero matrix")

    registry = records["FABRIC-STORE-REGISTRY-1"]
    registry_digest = hashlib.sha256(
        b"NINLIL-FABRIC-REGISTRY-RECORD-V1"
        + bytes.fromhex(registry["key_hex"])
        + bytes.fromhex(registry["value_hex"])
    ).digest()
    attempt = bytes.fromhex(records["FABRIC-STORE-ATTEMPT-1"]["value_hex"])
    require(attempt[272:304] == registry_digest, "FBA registry digest")
    require(be64(attempt[636:644]) == 200000, "durable retry expiry")
    require(
        attempt[536:552] == attempt[488:504] == attempt[620:636],
        "retry/deadline/availability clock epoch",
    )
    require(attempt[684:700] != b"\0" * 16, "durable permit ID")
    require(be64(attempt[700:708]) == 450000, "durable permit expiry")
    require(be32(attempt[708:712]) == 1, "durable retained permit claim")
    attempt_facts = records["FABRIC-STORE-ATTEMPT-1"]["facts"]
    require(
        attempt_facts["permit_clock_epoch_id_hex"]
        == attempt_facts["retry_lifetime_clock_epoch_id_hex"],
        "permit clock fact reuses retry lifetime epoch",
    )
    require(
        attempt_facts["permit_id_hex"] == attempt[684:700].hex()
        and attempt_facts["permit_expires_at_ms"] == be64(attempt[700:708])
        and attempt_facts["permit_claim_state"] == be32(attempt[708:712]),
        "permit facts match FBA1",
    )
    require(
        attempt_facts["retry_expires_at_ms"]
        == min(
            attempt_facts["message_deadline_ms"],
            attempt_facts["availability_expires_at_ms"],
            attempt_facts["first_admit_ms"]
            + attempt_facts["retry_lifetime_cap_ms"],
        ),
        "retry lifetime formula",
    )

    require(
        set(SELECTION_SEMANTICS) == set(ACTUAL_SELECTION_IDS),
        "selection: SELECTION_SEMANTICS must cover exact actual IDs",
    )
    require(
        len(ACTUAL_SELECTION_IDS) == 46
        and len(set(ACTUAL_SELECTION_IDS)) == 46,
        "selection: internal actual ID inventory must be exact 46",
    )
    expected_selection_ids = ACTUAL_SELECTION_IDS + tuple(SELECTION_RACE_CASES)
    require(
        len(SELECTION_RACE_CASES) == 2
        and len(expected_selection_ids) == 48
        and len(set(expected_selection_ids)) == 48,
        "selection: internal complete ID inventory must be exact 48",
    )
    all_selection_rows = exact_id_map(
        document["selection_vectors"],
        expected_selection_ids,
        "selection",
    )
    selection_rows = {
        vector_id: all_selection_rows[vector_id]
        for vector_id in ACTUAL_SELECTION_IDS
    }
    require(
        all("inputs" in row and "model" in row for row in selection_rows.values()),
        "selection: actual vector missing inputs/model",
    )
    for vector_id, expected in SELECTION_RACE_CASES.items():
        require(
            all_selection_rows[vector_id] == {"id": vector_id, **expected},
            f"{vector_id}: exact event/side-effect/result",
        )
    for vector_id, row in selection_rows.items():
        mutation = row.get("mutation")
        baseline_id = (
            mutation.get(
                "baseline_id", "FABRIC-SELECT-ACTUAL-JOIN-BASELINE"
            )
            if mutation
            else vector_id
        )
        baseline = selection_rows[baseline_id]["inputs"]
        projected = project_durable_selection(
            row["inputs"],
            query=baseline["query"],
            active_attempts=baseline["active_attempts"],
            label=vector_id,
        )
        if mutation:
            apply_declared_mutation(projected, mutation)
        require(
            normalized_selection_inputs(projected)
            == normalized_selection_inputs(row["inputs"]),
            f"{vector_id}: semantic inputs diverge from durable projection",
        )
        selected, rejection = selection_decision(projected)
        require(
            selected == row["model"]["selected_instance_id_hex"],
            f"{vector_id}: durable selected",
        )
        require(
            rejection == row["model"]["primary_rejection"],
            f"{vector_id}: durable rejection",
        )
        assert_selection_semantics(vector_id, row)
        if mutation:
            rebuilt = copy.deepcopy(selection_rows[baseline_id]["inputs"])
            apply_declared_mutation(rebuilt, mutation)
            require(
                rebuilt == row["inputs"],
                f"{vector_id}: single mutation",
            )

    require(len(FBA_CASES) == 12, "FBA state transition: internal exact 12")
    fba = exact_id_map(
        document["fba_state_transition_vectors"],
        tuple(FBA_CASES),
        "FBA state transition",
    )
    require(REQUIRED_FBA_IDS <= set(fba), "missing FBA transition vectors")
    for vector_id, row in fba.items():
        require(len(row["old_rows"]) == len(row["new_rows"]) == 1, vector_id)
        old_key, old_value = parse_record(
            row["old_rows"][0]["key_hex"], row["old_rows"][0]["value_hex"], vector_id
        )
        new_key, new_value = parse_record(
            row["new_rows"][0]["key_hex"], row["new_rows"][0]["value_hex"], vector_id
        )
        require(old_key == new_key, f"{vector_id}: key changed")
        old_norm = bytearray(old_value)
        new_norm = bytearray(new_value)
        for mutable in (old_norm, new_norm):
            mutable[12:24] = b"\0" * 12
            mutable[64:68] = b"\0" * 4
            mutable[676:684] = b"\0" * 8
            mutable[708:712] = b"\0" * 4
            if row.get("fresh_permit_pair") == 1:
                mutable[684:708] = b"\0" * 24
        require(old_norm == new_norm, f"{vector_id}: immutable FBA changed")
        old_revision = be64(old_value[12:20])
        new_revision = be64(new_value[12:20])
        old_state = be32(old_value[64:68])
        new_state = be32(new_value[64:68])
        expected_states, expected_meta = FBA_CASES[vector_id]
        require(
            (old_state, new_state) == expected_states,
            f"{vector_id}: case state transition",
        )
        require(
            be32(old_value[708:712]) == row["permit_claim_before"]
            and be32(new_value[708:712]) == row["permit_claim_after"],
            f"{vector_id}: permit claim transition",
        )
        require(
            old_value[620:636] == new_value[620:636],
            f"{vector_id}: permit clock epoch immutable",
        )
        if row.get("fresh_permit_pair") == 1:
            require(
                old_value[684:700] != new_value[684:700],
                f"{vector_id}: fresh permit ID",
            )
            require(
                be64(old_value[700:708]) != 0
                and be64(new_value[700:708]) != 0,
                f"{vector_id}: fresh permit expiry",
            )
        else:
            require(
                old_value[684:708] == new_value[684:708],
                f"{vector_id}: permit pair immutable",
            )
        actual_meta = {
            key: value
            for key, value in row.items()
            if key not in ("id", "old_rows", "new_rows")
        }
        require(
            actual_meta == expected_meta,
            f"{vector_id}: case outcome/side effects",
        )
        if row.get("storage_mutations") == 0:
            require(old_value == new_value, f"{vector_id}: no-op bytes")
        else:
            require(
                new_revision == old_revision + 1,
                f"{vector_id}: revision not exact +1",
            )
        if "retry_expires_at_ms" in row:
            require(
                be64(old_value[636:644])
                == be64(new_value[636:644])
                == row["retry_expires_at_ms"],
                f"{vector_id}: durable retry expiry",
            )
            if vector_id.endswith("BEFORE-EXPIRY") or vector_id.endswith(
                "TO-PREPARED"
            ):
                require(
                    row["retry_now_ms"] < row["retry_expires_at_ms"],
                    f"{vector_id}: exclusive retry window",
                )
            else:
                require(
                    row["retry_now_ms"] >= row["retry_expires_at_ms"],
                    f"{vector_id}: expired retry window",
                )
        expected_terminal = row.get("runtime_terminal_revision", 0)
        require(
            be64(new_value[676:684]) == expected_terminal,
            f"{vector_id}: terminal revision",
        )
        if expected_terminal:
            require(
                be64(old_value[676:684]) == 0,
                f"{vector_id}: old terminal revision",
            )

    cu = {row["id"]: row for row in document["fba_commit_unknown_vectors"]}
    require(REQUIRED_FBA_CU_IDS <= set(cu), "missing FBA CU vectors")
    for vector_id, row in cu.items():
        old = row["old_rows"]
        new = row["new_rows"]
        observed = row["observed_rows"]
        for group_name, group in (("old", old), ("new", new), ("observed", observed)):
            for item in group:
                parse_record(item["key_hex"], item["value_hex"], f"{vector_id}:{group_name}")
        if row["classification"] == "OLD":
            require(observed == old, f"{vector_id}: OLD")
        elif row["classification"] == "NEW":
            require(observed == new, f"{vector_id}: NEW")
        else:
            require(observed != old and observed != new, f"{vector_id}: third")
            require(
                row["outer_result"] == "CORRUPT",
                f"{vector_id}: third outer result",
            )

    require(len(FRESH_CASES) == 11, "fresh adoption: internal exact 11")
    fresh = exact_id_map(
        document["fresh_adoption_vectors"],
        tuple(FRESH_CASES),
        "fresh adoption",
    )
    require(REQUIRED_FRESH_IDS <= set(fresh), "missing fresh/existing vectors")
    canonical_fbm = {
        "key_hex": records["FABRIC-STORE-META-1"]["key_hex"],
        "value_hex": records["FABRIC-STORE-META-1"]["value_hex"],
    }
    count_limits = {
        b"FBM1": 1,
        b"FBR1": 16,
        b"FBP1": 64,
        b"FBC1": 64,
        b"FBA1": 64,
        b"FBT1": 64,
    }
    for vector_id, row in fresh.items():
        actual_meta = {
            key: value
            for key, value in row.items()
            if key
            not in ("id", "old_rows", "new_rows", "observed_rows", "put_rows")
        }
        require(
            actual_meta == FRESH_CASES[vector_id],
            f"{vector_id}: case outcome",
        )
        for group_name in ("old_rows", "new_rows", "observed_rows", "put_rows"):
            for item in row.get(group_name, []):
                parse_record(
                    item["key_hex"],
                    item["value_hex"],
                    f"{vector_id}:{group_name}",
                )
        observed = row.get("observed_rows", [])
        if row["phase"] == "READ_ONLY_SCAN":
            require(not observed, f"{vector_id}: fresh read-only zero")
        elif row["phase"] == "READ_WRITE_RESCAN":
            if vector_id == "FABRIC-FRESH-READ-WRITE-ZERO-ROWS":
                require(not observed, f"{vector_id}: read-write zero")
                require(
                    row.get("put_rows") == [canonical_fbm],
                    f"{vector_id}: canonical FBM1 put",
                )
            else:
                require(observed, f"{vector_id}: race observed")
                require(
                    not row.get("put_rows"), f"{vector_id}: race mutation zero"
                )
        elif row["phase"] == "REOPEN_READ_CLASSIFY":
            old = row.get("old_rows", [])
            new = row.get("new_rows", [])
            classification = (
                "ABSENT"
                if observed == old == []
                else "NEW"
                if observed == new
                else "CORRUPT"
            )
            require(
                row["classification"] == classification,
                f"{vector_id}: fresh reopen classification",
            )
            require(
                row["create_result"] == "COMMIT_UNKNOWN_NO_PUBLISH",
                f"{vector_id}: fresh reopen result",
            )
        else:
            keys = [bytes.fromhex(item["key_hex"]) for item in observed]
            strict_order = all(
                left < right for left, right in zip(keys, keys[1:])
            )
            counts = {
                magic: sum(key.startswith(magic) for key in keys)
                for magic in count_limits
            }
            valid_existing = (
                strict_order
                and counts[b"FBM1"] == 1
                and all(
                    counts[magic] <= limit
                    for magic, limit in count_limits.items()
                )
            )
            classification = "EXISTING" if valid_existing else "CORRUPT"
            require(
                row["classification"] == classification,
                f"{vector_id}: existing reopen classification",
            )
            require(
                row["registry_publish"] == int(valid_existing),
                f"{vector_id}: reopen publish",
            )
    overflow = fresh["FABRIC-EXISTING-COUNT-OVERFLOW"]
    count = sum(
        bytes.fromhex(row["key_hex"]).startswith(b"FBP1")
        for row in overflow["observed_rows"]
    )
    require(count == 65, "existing policy overflow count")
    duplicate = fresh["FABRIC-EXISTING-DUPLICATE-KEY"]["observed_rows"]
    require(
        len({row["key_hex"] for row in duplicate}) != len(duplicate),
        "existing duplicate proof",
    )
    out_of_order = fresh["FABRIC-EXISTING-OUT-OF-ORDER"]["observed_rows"]
    keys = [bytes.fromhex(row["key_hex"]) for row in out_of_order]
    require(keys != sorted(keys), "existing order proof")

    require(
        REQUIRED_STORAGE_NEGATIVE_IDS
        <= {row["id"] for row in document["storage_negative_vectors"]},
        "missing FBC negatives",
    )
    for row in document["storage_negative_vectors"]:
        value = bytes.fromhex(row["value_hex"])
        if row["expected"] == "REJECT_RECORD_CRC32C":
            require(not record_crc_ok(value), f"{row['id']}: CRC mutation")
        else:
            require(record_crc_ok(value), f"{row['id']}: repaired CRC")
        if row["id"].startswith("FABRIC-STORE-POLICY-UNKNOWN-"):
            payload = bytearray(value[24:])
            stored = bytes(payload[24:56])
            payload[24:56] = b"\0" * 32
            require(
                stored
                == hashlib.sha256(
                    b"NINLIL-FABRIC-POLICY-V1" + bytes(payload)
                ).digest(),
                f"{row['id']}: repaired canonical digest",
            )
        if row["id"] in STORAGE_ENUM_NEGATIVE_IDS:
            try:
                parse_record(
                    row["key_hex"],
                    row["value_hex"],
                    row["id"],
                )
            except GateError:
                pass
            else:
                raise GateError(
                    f"{row['id']}: closed enum fixture was accepted"
                )
    require(
        REQUIRED_NFL_NEGATIVE_IDS
        <= {row["id"] for row in document["nfl1_negative_vectors"]},
        "missing NFL enum negatives",
    )
    for row in document["nfl1_negative_vectors"]:
        if row["id"] in REQUIRED_NFL_NEGATIVE_IDS:
            require(
                nfl1_closed_enum_error(bytes.fromhex(row["encoded_hex"]))
                == row["expected"],
                f"{row['id']}: NFL closed enum rejection",
            )
    require(
        "FABRIC-NFL1-ABSENT-AUTHORITY-MIN"
        in {row["id"] for row in document["nfl1_positive_vectors"]},
        "missing ABSENT NFL1",
    )


NODE_ORACLE = r"""
const fs = require('fs');
const crypto = require('crypto');
const doc = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const sizes = {FBM1:64,FBR1:372,FBP1:352,FBC1:512,FBA1:712,FBT1:248};
const keySizes = {FBM1:4,FBR1:20,FBP1:28,FBC1:20,FBA1:76,FBT1:40};
function fail(m){ throw new Error(m); }
function u16(b,o){ return b.readUInt16BE(o); }
function u32(b,o){ return b.readUInt32BE(o); }
function u64(b,o){ return b.readBigUInt64BE(o); }
function crc32c(buf){
  let crc = 0xffffffff;
  for (const octet of buf) {
    crc = (crc ^ octet) >>> 0;
    for (let i=0;i<8;i++) crc = ((crc>>>1) ^ ((crc&1)?0x82f63b78:0)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function sha(buf){ return crypto.createHash('sha256').update(buf).digest(); }
function check(keyHex,valueHex,label){
  const k=Buffer.from(keyHex,'hex'), v=Buffer.from(valueHex,'hex');
  const magic=v.subarray(0,4).toString('ascii');
  if (!(magic in sizes) || v.length!==sizes[magic]) fail(label+': size/magic');
  if (!k.subarray(0,4).equals(v.subarray(0,4))) fail(label+': key magic');
  if (k.length!==keySizes[magic]) fail(label+': key size');
  if (u16(v,4)!==1 || u16(v,6)!==24 || u32(v,8)!==v.length || u64(v,12)===0n)
    fail(label+': envelope');
  const c=Buffer.from(v), stored=u32(c,20); c.fill(0,20,24);
  if (crc32c(c)!==stored) fail(label+': crc');
  if (magic==='FBP1') {
    if (!k.subarray(4,20).equals(v.subarray(24,40))
        || !k.subarray(20,28).equals(v.subarray(40,48)))
      fail(label+': policy key');
    const p=Buffer.from(v.subarray(24)), storedDigest=Buffer.from(p.subarray(24,56));
    p.fill(0,24,56);
    if (!storedDigest.equals(sha(Buffer.concat([Buffer.from('NINLIL-FABRIC-POLICY-V1'),p]))))
      fail(label+': policy digest');
    if (u32(v,112)!==2 || ![1,2].includes(u32(v,116))
        || ![1,2].includes(u16(v,122)) || ![0,1].includes(v[140]))
      fail(label+': policy enum');
  }
  if (magic==='FBM1' && u16(v,28)!==1) fail(label+': migration state');
  if (magic==='FBR1') {
    if (!k.subarray(4,20).equals(v.subarray(24,40)))
      fail(label+': instance key');
    if (![1,2,3,4].includes(u32(v,40)) || ![0,1].includes(v[312])
        || ![1,2].includes(v[313]) || u16(v,324)!==1)
      fail(label+': registry enum');
  }
  if (magic==='FBC1') {
    if (!k.subarray(4,20).equals(v.subarray(24,40)))
      fail(label+': binding key');
    const selector=u16(v,82), state=u32(v,188);
    if (![1,2].includes(selector) || ![0,1].includes(state)) fail(label+': FBC enum');
    if (selector===2 && !v.subarray(84,100).equals(v.subarray(100,116)))
      fail(label+': target endpoint');
    if (state===0) {
      if (!v.subarray(188,496).equals(Buffer.alloc(308))) fail(label+': ABSENT matrix');
    } else {
      const owner=sha(Buffer.concat([Buffer.from('NINLIL-FABRIC-OWNER-TUPLE-V1'),
                                     v.subarray(272,472)]));
      if (!owner.equals(v.subarray(240,272))) fail(label+': owner digest');
    }
  }
  if (magic==='FBA1') {
    if (!k.subarray(4,20).equals(v.subarray(24,40))
        || !k.subarray(20,36).equals(v.subarray(40,56))
        || !k.subarray(36,40).equals(v.subarray(56,60))
        || !k.subarray(40,44).equals(v.subarray(60,64))
        || !k.subarray(44,76).equals(v.subarray(68,100))) fail(label+': FBA key');
    if (v.subarray(620,636).equals(Buffer.alloc(16)) || u64(v,636)===0n)
      fail(label+': retry lifetime');
    const dispatch=sha(Buffer.concat([Buffer.from('NINLIL-FABRIC-LOCAL-DISPATCH-V1'),k]));
    if (!dispatch.equals(v.subarray(644,676))) fail(label+': dispatch');
    const state=u32(v,64), claim=u32(v,708);
    if (state<1 || state>6) fail(label+': FBA state');
    if (v.subarray(684,700).equals(Buffer.alloc(16)) || u64(v,700)===0n)
      fail(label+': permit authority');
    if (![0,1].includes(claim)) fail(label+': permit claim state');
    if (state===2 && claim!==1) fail(label+': LINK_RETAINED keeps CLAIMED');
    if (state===3 && claim!==0) fail(label+': RETRYABLE keeps CLEAR');
  }
  if (magic==='FBT1') {
    if (!k.subarray(4,20).equals(v.subarray(24,40))
        || !k.subarray(20,36).equals(v.subarray(40,56))
        || !k.subarray(36,40).equals(v.subarray(56,60)))
      fail(label+': trigger key');
    if (![1,4].includes(u32(v,56)) || ![0,1].includes(u32(v,60)))
      fail(label+': trigger enum');
  }
  return {k,v,magic};
}
function clone(x){ return JSON.parse(JSON.stringify(x)); }
function stable(x){
  if (Array.isArray(x)) return '['+x.map(stable).join(',')+']';
  if (x && typeof x==='object')
    return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+stable(x[k])).join(',')+'}';
  return JSON.stringify(x);
}
function withoutSource(x){
  const y=clone(x);
  if (y && typeof y==='object' && !Array.isArray(y)) delete y.source_record_id;
  return y;
}
function applyMutation(base,mutation){
  let cursor=base;
  for (const part of mutation.path) cursor=cursor[part];
  if (mutation.operation==='replace') {
    if (stable(cursor)!==stable(mutation.old)) fail('selection mutation old mismatch');
    let parent=base;
    for (const part of mutation.path.slice(0,-1)) parent=parent[part];
    parent[mutation.path.at(-1)]=clone(mutation.new);
  } else if (mutation.operation==='append') {
    cursor.push(clone(mutation.new));
  } else if (mutation.operation==='remove') {
    const wanted=stable(withoutSource(mutation.old));
    const index=cursor.findIndex(item=>stable(withoutSource(item))===wanted);
    if (index<0) fail('selection remove old mismatch');
    cursor.splice(index,1);
  } else fail('selection mutation operation');
}
function projectSelection(input,query,active,label){
  const decoded={FBM1:[],FBR1:[],FBP1:[],FBC1:[],FBA1:[],FBT1:[]};
  for (const [name,row] of Object.entries(input.durable_rows)) {
    const parsed=check(row.key_hex,row.value_hex,label+':'+name);
    decoded[parsed.magic].push(parsed);
  }
  if (decoded.FBM1.length!==1) fail(label+': exact FBM1');
  const mv=decoded.FBM1[0].v;
  const meta={
    record_revision:Number(u64(mv,12)),
    outer_availability_epoch:Number(u64(mv,48)),
    outer_available:u32(mv,56),
  };
  const registry=decoded.FBR1.map(({k,v})=>{
    if (!k.subarray(4,20).equals(v.subarray(24,40))) fail(label+': FBR identity');
    return {
      instance_id_hex:v.subarray(24,40).toString('hex'),
      record_revision:Number(u64(v,12)),
      lifecycle:({1:'ACTIVE',2:'DRAINING'})[v[313]],
      direction_mask:u32(v,44),
      link_kind:({1:'LOOPBACK',2:'WIFI',3:'USB',4:'RF'})[u32(v,40)],
      capability_flags:u32(v,48),
      maximum_packet_bytes:u32(v,272),
      maximum_transfer_bytes:u32(v,276),
      latency_class:u16(v,280),
      cost_class:u16(v,282),
      reservation_capacity:u16(v,284),
      security_capability_flags:u32(v,108),
      peer_nfl1_version:u16(v,324),
      peer_fabric_capability_flags:u32(v,328),
      authenticated_peer_runtime_id_hex:v.subarray(208,224).toString('hex'),
      attachment_authority_id_hex:v.subarray(224,240).toString('hex'),
      attachment_binding_digest_hex:v.subarray(240,272).toString('hex'),
      attestation_epoch:Number(u64(v,144)),
      attestation_clock_epoch_id_hex:v.subarray(152,168).toString('hex'),
      attestation_expires_at_ms:Number(u64(v,168)),
      availability_epoch:Number(u64(v,288)),
      availability_clock_epoch_id_hex:v.subarray(296,312).toString('hex'),
      availability_state:v[312],
      availability_expires_at_ms:Number(u64(v,316)),
    };
  });
  const groups=new Map();
  for (const {k,v} of decoded.FBP1) {
    const id=v.subarray(24,40).toString('hex'), revision=Number(u64(v,40));
    if (!k.subarray(4,20).equals(v.subarray(24,40)) || Number(u64(k,20))!==revision)
      fail(label+': FBP identity');
    if (!groups.has(id)) groups.set(id,[]);
    groups.get(id).push(v);
  }
  const policies=[];
  for (const [id,versions] of groups) {
    versions.sort((a,b)=>Number(u64(a,40)-u64(b,40)));
    const chain=versions.map(v=>Number(u64(v,40)));
    if (new Set(chain).size!==chain.length) fail(label+': duplicate FBP revision');
    const v=versions.at(-1), count=u16(v,152), candidates=[];
    if (count>8) fail(label+': FBP candidate count');
    for (let i=0;i<count;i++) {
      const o=160+i*24;
      candidates.push({
        instance_id_hex:v.subarray(o,o+16).toString('hex'),
        rank:u16(v,o+16),
        reservation_units:u16(v,o+20),
      });
    }
    policies.push({
      policy_id_hex:id,
      revision:Number(u64(v,40)),
      revision_chain:chain,
      canonical_digest_hex:v.subarray(48,80).toString('hex'),
      service_identity_digest_hex:v.subarray(80,112).toString('hex'),
      family:u32(v,112),
      direction:u32(v,116),
      traffic_class:u16(v,120),
      scope_selector:({1:'SOURCE_RUNTIME',2:'TARGET_RUNTIME'})[u16(v,122)],
      required_capability_flags:u32(v,124),
      required_security_flags:u32(v,128),
      maximum_latency_class:u16(v,132),
      maximum_cost_class:u16(v,134),
      minimum_packet_bytes:u32(v,136),
      authority_mode:({0:'ABSENT_ALLOWED',1:'BOUND_REQUIRED'})[v[140]],
      deadline_guard_ms:Number(u64(v,144)),
      candidates,
    });
  }
  const authorities=decoded.FBC1.map(({k,v})=>{
    if (!k.subarray(4,20).equals(v.subarray(24,40))) fail(label+': FBC identity');
    return {
      binding_id_hex:v.subarray(24,40).toString('hex'),
      service_identity_digest_hex:v.subarray(40,72).toString('hex'),
      family:u32(v,72),
      direction:u32(v,76),
      traffic_class:u16(v,80),
      scope_selector:({1:'SOURCE_RUNTIME',2:'TARGET_RUNTIME'})[u16(v,82)],
      endpoint_runtime_id_hex:v.subarray(84,100).toString('hex'),
      target_runtime_id_hex:v.subarray(100,116).toString('hex'),
      target_application_id_hex:v.subarray(116,132).toString('hex'),
      policy_id_hex:v.subarray(132,148).toString('hex'),
      policy_revision:Number(u64(v,148)),
      policy_digest_hex:v.subarray(156,188).toString('hex'),
      authority_state:u32(v,188)===0?'ABSENT':'BOUND',
      authority_clock_epoch_id_hex:v.subarray(472,488).toString('hex'),
      lease_expires_at_ms:Number(u64(v,488)),
    };
  });
  return {meta,query:clone(query),policies,registry,authorities,
          active_attempts:clone(active)};
}
function normalizedInputs(input){
  const out={};
  for (const name of ['meta','query','policies','registry','authorities','active_attempts'])
    out[name]=clone(input[name]);
  delete out.meta.source_record_id;
  for (const name of ['policies','registry','authorities'])
    for (const row of out[name]) delete row.source_record_id;
  out.policies.sort((a,b)=>a.policy_id_hex.localeCompare(b.policy_id_hex));
  out.registry.sort((a,b)=>a.instance_id_hex.localeCompare(b.instance_id_hex));
  out.authorities.sort((a,b)=>a.binding_id_hex.localeCompare(b.binding_id_hex));
  return out;
}
function selectionDecision(s){
  const q=s.query;
  if (s.meta.outer_available!==1) return [null,'META_OUTER_UNAVAILABLE'];
  for (const p of s.policies) {
    const c=p.revision_chain;
    if (!c.length || c.at(-1)!==p.revision || c.some((v,i)=>i && v!==c[i-1]+1))
      return [null,'POLICY_REVISION_GAP'];
  }
  const ps=s.policies.filter(p=>p.service_identity_digest_hex===q.service_identity_digest_hex
    && p.family===q.family && p.direction===q.direction && p.traffic_class===q.traffic_class);
  if (!ps.length) return [null,'POLICY_NO_MATCH'];
  if (ps.length!==1) return [null,'POLICY_AMBIGUOUS'];
  const p=ps[0], endpoint=q[p.scope_selector==='SOURCE_RUNTIME'
    ?'source_runtime_id_hex':'target_runtime_id_hex'];
  let first=null; const eligible=[];
  for (const c of p.candidates) {
    const rs=s.registry.filter(r=>r.instance_id_hex===c.instance_id_hex);
    if (rs.length!==1) {
      first ||= rs.length?'REGISTRY_JOIN_AMBIGUOUS':'REGISTRY_JOIN_MISSING';
      continue;
    }
    const r=rs[0], as=s.authorities.filter(a=>
      a.service_identity_digest_hex===q.service_identity_digest_hex
      && a.family===q.family && a.direction===q.direction
      && a.traffic_class===q.traffic_class && a.scope_selector===p.scope_selector
      && a.endpoint_runtime_id_hex===endpoint
      && a.target_runtime_id_hex===q.target_runtime_id_hex
      && a.target_application_id_hex===q.target_application_id_hex
      && a.policy_id_hex===p.policy_id_hex && a.policy_revision===p.revision
      && a.policy_digest_hex===p.canonical_digest_hex);
    const reasons=[]; const a=as.length===1?as[0]:null;
    if (as.length!==1) reasons.push(as.length?'AUTHORITY_JOIN_AMBIGUOUS':'AUTHORITY_JOIN_MISSING');
    // Hard-filter chain after join (Normative order; primary = first).
    if (r.lifecycle!=='ACTIVE') reasons.push('LIFECYCLE_DRAINING');
    if ((r.direction_mask&1)===0) reasons.push('DIRECTION_MISMATCH');
    if (q.packet_bytes<587) reasons.push('STRUCTURAL_LENGTH_FLOOR');
    if (q.packet_bytes>1925) reasons.push('STRUCTURAL_LENGTH_CEILING');
    if (q.packet_bytes<p.minimum_packet_bytes) reasons.push('PACKET_MINIMUM');
    if (q.packet_bytes>r.maximum_packet_bytes) reasons.push('PACKET_MTU');
    if (q.transfer_bytes>r.maximum_transfer_bytes) reasons.push('TRANSFER_MTU');
    if (r.latency_class>p.maximum_latency_class) reasons.push('LATENCY_CLASS');
    if (r.cost_class>p.maximum_cost_class) reasons.push('COST_CLASS');
    if (q.deadline_ms-q.now_ms<p.deadline_guard_ms) reasons.push('DEADLINE_GUARD');
    if (q.deadline_clock_epoch_id_hex!==q.admission_clock_epoch_id_hex
        || q.deadline_clock_epoch_id_hex!==q.availability_clock_epoch_id_hex)
      reasons.push('RETRY_LIFETIME_CLOCK_EPOCH');
    const used=s.active_attempts.filter(x=>x.instance_id_hex===c.instance_id_hex
      && ['PREPARED','LINK_RETAINED'].includes(x.state))
      .reduce((n,x)=>n+x.reservation_units,0);
    if (used+c.reservation_units>r.reservation_capacity) reasons.push('RESERVATION_CAPACITY');
    const caps=p.required_capability_flags|q.required_capability_flags;
    if ((r.capability_flags&caps)!==caps) reasons.push('CAPABILITY_MISSING');
    if (q.requires_sleep_compatible && (r.capability_flags&1)===0)
      reasons.push('ENERGY_SLEEP_CAPABILITY_MISSING');
    const sec=p.required_security_flags|q.required_security_flags;
    if ((r.security_capability_flags&sec)!==sec) reasons.push('SECURITY_MISSING');
    if (q.requires_custody
        && (r.link_kind==='WIFI' || (r.capability_flags&0x20)===0))
      reasons.push('CUSTODY_MISSING');
    if (q.requires_evidence && (r.capability_flags&0x40)===0) reasons.push('EVIDENCE_MISSING');
    if (r.peer_nfl1_version!==1 || (r.peer_fabric_capability_flags&1)===0)
      reasons.push('PEER_NFL1');
    if (r.authenticated_peer_runtime_id_hex!==q.authenticated_peer_runtime_id_hex)
      reasons.push('AUTHENTICATED_PEER_MISMATCH');
    if (r.attachment_authority_id_hex!==q.attachment_authority_id_hex)
      reasons.push('ATTACHMENT_AUTHORITY_MISMATCH');
    if (r.attachment_binding_digest_hex!==q.attachment_binding_digest_hex)
      reasons.push('ATTACHMENT_BINDING_MISMATCH');
    if (r.attestation_clock_epoch_id_hex!==q.attestation_clock_epoch_id_hex)
      reasons.push('ATTESTATION_EPOCH');
    else if (q.now_ms>=r.attestation_expires_at_ms) reasons.push('ATTESTATION_EXPIRED');
    if (r.availability_clock_epoch_id_hex!==q.availability_clock_epoch_id_hex)
      reasons.push('AVAILABILITY_EPOCH');
    else if (r.availability_state!==1) reasons.push('AVAILABILITY_STATE');
    else if (q.now_ms>=r.availability_expires_at_ms) reasons.push('AVAILABILITY_EXPIRED');
    if (a) {
      if (p.authority_mode==='BOUND_REQUIRED' && a.authority_state!=='BOUND')
        reasons.push('BOUND_REQUIRED_ABSENT');
      else if (a.authority_state==='BOUND') {
        if (a.authority_clock_epoch_id_hex!==q.authority_clock_epoch_id_hex)
          reasons.push('AUTHORITY_CLOCK_EPOCH');
        else if (q.now_ms>=a.lease_expires_at_ms) reasons.push('AUTHORITY_LEASE_EXPIRED');
      }
    }
    if (r.link_kind==='RF') {
      if (!q.rf_permit_valid) reasons.push('RF_PERMIT');
      if (!q.rf_mapping_accepted) reasons.push('RF_MAPPING_UNSUPPORTED');
    }
    if (reasons.length) first ||= reasons[0];
    else eligible.push([[c.rank,r.latency_class,r.cost_class,c.instance_id_hex],c.instance_id_hex]);
  }
  eligible.sort((a,b)=>{
    for (let i=0;i<4;i++) if (a[0][i]!==b[0][i])
      return i===3?a[0][i].localeCompare(b[0][i]):a[0][i]-b[0][i];
    return 0;
  });
  return [eligible.length?eligible[0][1]:null,first];
}
function nflEnumError(v){
  if (v.length<570) return null;
  if (u16(v,4)!==1) return 'REJECT_UNKNOWN_VERSION';
  const kind=u32(v,16);
  if (![1,2,3,4,5,6].includes(kind)) return 'REJECT_UNKNOWN_MESSAGE_KIND';
  if (u16(v,308)!==1) return 'REJECT_UNKNOWN_DESCRIPTOR_DIGEST_ALGORITHM';
  if (![1,2,3,4,5,6,0x80000001].includes(u32(v,346))) return 'REJECT_UNKNOWN_FAMILY';
  if (u16(v,350)!==1) return 'REJECT_UNKNOWN_CONTENT_DIGEST_ALGORITHM';
  if (u16(v,508)!==1) return 'REJECT_UNKNOWN_ROUTE_DIGEST_ALGORITHM';
  if (kind===2) {
    if (![1,2,3,4].includes(u32(v,428))) return 'REJECT_UNKNOWN_RECEIPT_STAGE';
    if (![0,1,2].includes(u32(v,480))) return 'REJECT_UNKNOWN_EVIDENCE_TIME_TRUST';
  }
  if (kind===3) {
    if (u32(v,432)<1 || u32(v,432)>10) return 'REJECT_UNKNOWN_DISPOSITION';
    if (![1,2].includes(u32(v,436))) return 'REJECT_UNKNOWN_EFFECT_CERTAINTY';
    if (![0,1,2,3].includes(u32(v,440))) return 'REJECT_UNKNOWN_RETRY_GUIDANCE';
  }
  if (kind===6 && ![1,2,3].includes(u32(v,444))) return 'REJECT_UNKNOWN_CANCEL_KIND';
  return null;
}
function nflBoundaryResult(v){
  if (v.length>2048) return 'REJECT_CODEC_BUFFER_CEILING';
  if (v.length<587) return 'REJECT_STRUCTURAL_LENGTH_FLOOR';
  if (v.length>1925) return 'REJECT_STRUCTURAL_LENGTH_CEILING';
  if (v.subarray(0,4).toString('ascii')!=='NFL1'
      || u16(v,4)!==1 || u16(v,6)!==584 || u32(v,8)!==v.length)
    return 'REJECT_NFL1_FRAMING';
  const variableBytes=u16(v,570)+u16(v,572)+u16(v,574)+u32(v,576)+u32(v,580);
  if (584+variableBytes!==v.length) return 'REJECT_NFL1_FRAMING';
  const mutable=Buffer.from(v), stored=u32(mutable,12);
  mutable.fill(0,12,16);
  if (crc32c(mutable)!==stored) return 'REJECT_NFL1_FRAMING';
  if (u32(v,16)===1 && u32(v,576)>0 && u32(v,580)>0)
    return 'REJECT_KIND_MATRIX_PAYLOAD_AND_EVIDENCE';
  return 'ACCEPT';
}
for (const r of doc.storage_records) {
  check(r.key_hex,r.value_hex,r.id);
  const kv=Buffer.concat([Buffer.from(r.key_hex,'hex'),Buffer.from(r.value_hex,'hex')]);
  if (sha(kv).toString('hex')!==r.sha256_hex) fail(r.id+': sha');
}
const storageEnumIds=new Set([
  'FABRIC-STORE-META-UNKNOWN-MIGRATION-STATE',
  'FABRIC-STORE-REGISTRY-UNKNOWN-LINK-KIND',
  'FABRIC-STORE-REGISTRY-UNKNOWN-AVAILABILITY-STATE',
  'FABRIC-STORE-REGISTRY-UNKNOWN-LIFECYCLE',
  'FABRIC-STORE-REGISTRY-PEER-NFL1-V2',
  'FABRIC-STORE-POLICY-UNKNOWN-FAMILY',
  'FABRIC-STORE-POLICY-UNKNOWN-DIRECTION',
  'FABRIC-STORE-POLICY-UNKNOWN-SCOPE-SELECTOR',
  'FABRIC-STORE-POLICY-UNKNOWN-AUTHORITY-MODE',
  'FABRIC-STORE-AUTHORITY-SCOPE-SELECTOR-UNKNOWN',
  'FABRIC-STORE-AUTHORITY-UNKNOWN-STATE',
  'FABRIC-STORE-ATTEMPT-UNKNOWN-STATE',
  'FABRIC-STORE-TRIGGER-UNKNOWN-KIND',
  'FABRIC-STORE-TRIGGER-UNKNOWN-AUTHORITY-STATE',
]);
for (const row of doc.storage_negative_vectors) if (storageEnumIds.has(row.id)) {
  let rejected=false;
  try { check(row.key_hex,row.value_hex,row.id); } catch (_) { rejected=true; }
  if (!rejected) fail(row.id+': closed enum fixture was accepted');
}
for (const row of doc.nfl1_positive_vectors) {
  if (nflEnumError(Buffer.from(row.encoded_hex,'hex'))!==null)
    fail(row.id+': positive closed enum');
}
const nflEnumIds=new Set([
  'FABRIC-NFL1-UNKNOWN-RECEIPT-STAGE',
  'FABRIC-NFL1-UNKNOWN-DISPOSITION',
  'FABRIC-NFL1-UNKNOWN-EFFECT-CERTAINTY',
  'FABRIC-NFL1-UNKNOWN-RETRY-GUIDANCE',
  'FABRIC-NFL1-UNKNOWN-CANCEL-KIND',
  'FABRIC-NFL1-UNKNOWN-FAMILY',
  'FABRIC-NFL1-UNKNOWN-EVIDENCE-TRUST',
  'FABRIC-NFL1-UNKNOWN-DESCRIPTOR-DIGEST-ALGORITHM',
  'FABRIC-NFL1-UNKNOWN-CONTENT-DIGEST-ALGORITHM',
  'FABRIC-NFL1-UNKNOWN-ROUTE-DIGEST-ALGORITHM',
]);
for (const row of doc.nfl1_negative_vectors) if (nflEnumIds.has(row.id)) {
  if (nflEnumError(Buffer.from(row.encoded_hex,'hex'))!==row.expected)
    fail(row.id+': NFL closed enum rejection');
}
const positiveNfl1=new Map(doc.nfl1_positive_vectors.map(row=>[row.id,row]));
const negativeNfl1=new Map(doc.nfl1_negative_vectors.map(row=>[row.id,row]));
if (positiveNfl1.size!==doc.nfl1_positive_vectors.length)
  fail('duplicate NFL1 positive vector ID');
if (negativeNfl1.size!==doc.nfl1_negative_vectors.length)
  fail('duplicate NFL1 negative vector ID');
const nflBoundaryCases={
  'FABRIC-NFL1-APPLICATION-MIN':['positive',587,'ACCEPT'],
  'FABRIC-NFL1-STRUCTURAL-1925-SEMANTIC-REJECT':
    ['negative',1925,'REJECT_KIND_MATRIX_PAYLOAD_AND_EVIDENCE'],
  'FABRIC-NFL1-STRUCTURAL-LENGTH-1926':
    ['negative',1926,'REJECT_STRUCTURAL_LENGTH_CEILING'],
  'FABRIC-NFL1-CODEC-BUFFER-2049':
    ['negative',2049,'REJECT_CODEC_BUFFER_CEILING'],
  'FABRIC-NFL1-STRUCTURAL-LENGTH-586':
    ['negative',586,'REJECT_STRUCTURAL_LENGTH_FLOOR'],
};
for (const [id,[collection,expectedLength,expected]] of
     Object.entries(nflBoundaryCases)) {
  const row=(collection==='positive'?positiveNfl1:negativeNfl1).get(id);
  if (!row) fail(id+': missing NFL1 boundary vector');
  const packet=Buffer.from(row.encoded_hex,'hex');
  if (packet.length!==expectedLength || row.encoded_length!==expectedLength)
    fail(id+': exact NFL1 boundary length');
  if (sha(packet).toString('hex')!==row.sha256_hex)
    fail(id+': NFL1 boundary sha');
  if ((row.expected??'ACCEPT')!==expected)
    fail(id+': exact NFL1 boundary expectation');
  if (nflBoundaryResult(packet)!==expected)
    fail(id+': independent NFL1 boundary classification');
}
const actualSelectionIds=[
  'FABRIC-SELECT-ACTUAL-JOIN-BASELINE',
  'FABRIC-SELECT-POLICY-NO-MATCH',
  'FABRIC-SELECT-POLICY-AMBIGUOUS',
  'FABRIC-SELECT-POLICY-REVISION-GAP',
  'FABRIC-SELECT-REGISTRY-JOIN-MISSING',
  'FABRIC-SELECT-AUTHORITY-JOIN-MISSING',
  'FABRIC-SELECT-AUTHORITY-JOIN-AMBIGUOUS',
  'FABRIC-SELECT-LIFECYCLE-DRAINING',
  'FABRIC-SELECT-DIRECTION-MISMATCH',
  'FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR',
  'FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING',
  'FABRIC-SELECT-LATENCY-CLASS',
  'FABRIC-SELECT-COST-CLASS',
  'FABRIC-SELECT-DEADLINE-GUARD',
  'FABRIC-SELECT-RETRY-LIFETIME-CLOCK-EPOCH',
  'FABRIC-SELECT-RESERVATION-CAPACITY',
  'FABRIC-SELECT-CAPABILITY-MISSING',
  'FABRIC-SELECT-ENERGY-SLEEP-CAPABILITY-MISSING',
  'FABRIC-SELECT-SECURITY-MISSING',
  'FABRIC-SELECT-CUSTODY-MISSING',
  'FABRIC-SELECT-EVIDENCE-MISSING',
  'FABRIC-SELECT-PEER-NFL1-UNSUPPORTED',
  'FABRIC-SELECT-AUTHENTICATED-PEER-MISMATCH',
  'FABRIC-SELECT-ATTACHMENT-AUTHORITY-MISMATCH',
  'FABRIC-SELECT-ATTACHMENT-BINDING-MISMATCH',
  'FABRIC-SELECT-ATTESTATION-EPOCH',
  'FABRIC-SELECT-ATTESTATION-EXPIRED',
  'FABRIC-SELECT-AVAILABILITY-EPOCH',
  'FABRIC-SELECT-AVAILABILITY-STATE',
  'FABRIC-SELECT-AVAILABILITY-EXPIRED',
  'FABRIC-SELECT-AUTHORITY-CLOCK-EPOCH',
  'FABRIC-SELECT-AUTHORITY-LEASE-EXPIRED',
  'FABRIC-SELECT-META-OUTER-UNAVAILABLE',
  'FABRIC-SELECT-SOURCE-RUNTIME-ENDPOINT',
  'FABRIC-SELECT-ABSENT-ALLOWED',
  'FABRIC-SELECT-BOUND-REQUIRED-ABSENT',
  'FABRIC-SELECT-MTU-BASELINE',
  'FABRIC-SELECT-PACKET-MTU',
  'FABRIC-SELECT-TRANSFER-MTU',
  'FABRIC-SELECT-PACKET-MINIMUM',
  'FABRIC-SELECT-RF-MAPPING-BASELINE',
  'FABRIC-SELECT-RF-MAPPING-UNSUPPORTED',
  'FABRIC-SELECT-RF-NO-PERMIT',
  'FABRIC-SELECT-SAME-KIND-TWO-INSTANCES',
  'FABRIC-SELECT-STABLE-ID-TIEBREAK',
  'FABRIC-SELECT-HARD-FILTER-PRECEDENCE',
];
if (actualSelectionIds.length!==46
    || new Set(actualSelectionIds).size!==46)
  fail('selection: internal actual ID inventory must be exact 46');
const selectionRaceCases={
  'FABRIC-SELECT-AVAILABILITY-EPOCH-RACE':{
    event:'AVAILABILITY_EPOCH_CHANGED_BEFORE_PROVIDER_RETAIN',
    admission_epoch:7,
    pre_retain_epoch:8,
    provider_retained:0,
    provider_start_calls:0,
    same_attempt_reselect_calls:0,
    closed_full_replacement:1,
    result:'UNAVAILABLE_NO_RETAIN_NO_SAME_ATTEMPT_RESELECT',
  },
  'FABRIC-SELECT-POST-RETAIN-EPOCH-RACE':{
    event:'AVAILABILITY_EPOCH_CHANGED_AFTER_PROVIDER_RETAIN',
    fabric_retained_epoch:7,
    post_provider_retain_epoch:8,
    provider_retained:1,
    provider_start_calls:1,
    same_attempt_reselect_calls:0,
    track_provider_token_to_terminal:1,
    result:'ACCEPTED_TRACK_PROVIDER_TOKEN_TO_TERMINAL',
  },
};
const expectedSelectionIds=new Set([
  ...actualSelectionIds,
  ...Object.keys(selectionRaceCases),
]);
if (Object.keys(selectionRaceCases).length!==2
    || expectedSelectionIds.size!==48)
  fail('selection: internal complete ID inventory must be exact 48');
if (!Array.isArray(doc.selection_vectors)
    || doc.selection_vectors.length!==expectedSelectionIds.size)
  fail('selection: exact vector count');
const rawSelectionIds=doc.selection_vectors.map((row,index)=>{
  if (!row || typeof row!=='object' || Array.isArray(row)
      || typeof row.id!=='string')
    fail('selection['+index+']: vector/object ID');
  return row.id;
});
const allSelectionRows=new Map(
  doc.selection_vectors.map(v=>[v.id,v])
);
if (allSelectionRows.size!==rawSelectionIds.length)
  fail('selection: duplicate vector ID');
if ([...expectedSelectionIds].some(id=>!allSelectionRows.has(id))
    || [...allSelectionRows.keys()].some(id=>!expectedSelectionIds.has(id)))
  fail('selection: unknown/missing vector ID');
const selectionRows=new Map(
  actualSelectionIds.map(id=>[id,allSelectionRows.get(id)])
);
if (selectionRows.size!==46
    || [...selectionRows.values()].some(row=>!row.inputs || !row.model))
  fail('selection: actual vector missing inputs/model');
for (const [id,expected] of Object.entries(selectionRaceCases)) {
  if (stable(allSelectionRows.get(id))!==stable({id,...expected}))
    fail(id+': exact event/side-effect/result');
}
const hardFilterOrder=["LIFECYCLE_DRAINING", "DIRECTION_MISMATCH", "STRUCTURAL_LENGTH_FLOOR", "STRUCTURAL_LENGTH_CEILING", "PACKET_MINIMUM", "PACKET_MTU", "TRANSFER_MTU", "LATENCY_CLASS", "COST_CLASS", "DEADLINE_GUARD", "RETRY_LIFETIME_CLOCK_EPOCH", "RESERVATION_CAPACITY", "CAPABILITY_MISSING", "ENERGY_SLEEP_CAPABILITY_MISSING", "SECURITY_MISSING", "CUSTODY_MISSING", "EVIDENCE_MISSING", "PEER_NFL1", "AUTHENTICATED_PEER_MISMATCH", "ATTACHMENT_AUTHORITY_MISMATCH", "ATTACHMENT_BINDING_MISMATCH", "ATTESTATION_EPOCH", "ATTESTATION_EXPIRED", "AVAILABILITY_EPOCH", "AVAILABILITY_STATE", "AVAILABILITY_EXPIRED", "BOUND_REQUIRED_ABSENT", "AUTHORITY_CLOCK_EPOCH", "AUTHORITY_LEASE_EXPIRED", "RF_PERMIT", "RF_MAPPING_UNSUPPORTED"];
const selectionSemantics={"FABRIC-SELECT-ABSENT-ALLOWED":{"authority_count":1,"authority_mode":"ABSENT_ALLOWED","authority_state":"ABSENT","direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":1,"resolution":"SELECTED","selected_instance_id_hex":"6162636465666768696a6b6c6d6e6f70","transfer_bytes":587},"FABRIC-SELECT-ACTUAL-JOIN-BASELINE":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":1,"resolution":"SELECTED","selected_instance_id_hex":"6162636465666768696a6b6c6d6e6f70","transfer_bytes":587},"FABRIC-SELECT-ATTACHMENT-AUTHORITY-MISMATCH":{"authority_count":1,"direction_mask":3,"filter_index":19,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"42434445464748494a4b4c4d4e4f5051","mutation_op":"replace","mutation_path":["registry",0,"attachment_authority_id_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"ATTACHMENT_AUTHORITY_MISMATCH","registry_count":1,"rejection_reasons":["ATTACHMENT_AUTHORITY_MISMATCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-ATTACHMENT-BINDING-MISMATCH":{"authority_count":1,"direction_mask":3,"filter_index":20,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"cd204b528c0eed26f15d4d5d718c1b174b5e59940920016227a1730e22ffed37","mutation_op":"replace","mutation_path":["registry",0,"attachment_binding_digest_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"ATTACHMENT_BINDING_MISMATCH","registry_count":1,"rejection_reasons":["ATTACHMENT_BINDING_MISMATCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-ATTESTATION-EPOCH":{"authority_count":1,"direction_mask":3,"filter_index":21,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"a2a3a4a5a6a7a8a9aaabacadaeafb0b1","mutation_op":"replace","mutation_path":["registry",0,"attestation_clock_epoch_id_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"ATTESTATION_EPOCH","registry_count":1,"rejection_reasons":["ATTESTATION_EPOCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-ATTESTATION-EXPIRED":{"authority_count":1,"direction_mask":3,"filter_index":22,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":100000,"mutation_op":"replace","mutation_path":["registry",0,"attestation_expires_at_ms"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"ATTESTATION_EXPIRED","registry_count":1,"rejection_reasons":["ATTESTATION_EXPIRED"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AUTHENTICATED-PEER-MISMATCH":{"authority_count":1,"direction_mask":3,"filter_index":18,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"32333435363738393a3b3c3d3e3f4041","mutation_op":"replace","mutation_path":["registry",0,"authenticated_peer_runtime_id_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AUTHENTICATED_PEER_MISMATCH","registry_count":1,"rejection_reasons":["AUTHENTICATED_PEER_MISMATCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AUTHORITY-CLOCK-EPOCH":{"authority_count":1,"direction_mask":3,"filter_index":27,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"d2d3d4d5d6d7d8d9dadbdcdddedfe0e1","mutation_op":"replace","mutation_path":["authorities",0,"authority_clock_epoch_id_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AUTHORITY_CLOCK_EPOCH","registry_count":1,"rejection_reasons":["AUTHORITY_CLOCK_EPOCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AUTHORITY-JOIN-AMBIGUOUS":{"authority_binding_ids":["b8b9babbbcbdbebfc0c1c2c3c4c5c6c7","b9babbbcbdbebfc0c1c2c3c4c5c6c7c8"],"authority_count":2,"authority_policy_ids":["7172737475767778797a7b7c7d7e7f80","7172737475767778797a7b7c7d7e7f80"],"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_op":"append","mutation_path":["authorities"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AUTHORITY_JOIN_AMBIGUOUS","registry_count":1,"rejection_reasons":["AUTHORITY_JOIN_AMBIGUOUS"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AUTHORITY-JOIN-MISSING":{"authority_count":0,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_op":"remove","mutation_path":["authorities"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AUTHORITY_JOIN_MISSING","registry_count":1,"rejection_reasons":["AUTHORITY_JOIN_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AUTHORITY-LEASE-EXPIRED":{"authority_count":1,"direction_mask":3,"filter_index":28,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":100000,"mutation_op":"replace","mutation_path":["authorities",0,"lease_expires_at_ms"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AUTHORITY_LEASE_EXPIRED","registry_count":1,"rejection_reasons":["AUTHORITY_LEASE_EXPIRED"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AVAILABILITY-EPOCH":{"authority_count":1,"direction_mask":3,"filter_index":23,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"a2a3a4a5a6a7a8a9aaabacadaeafb0b1","mutation_op":"replace","mutation_path":["registry",0,"availability_clock_epoch_id_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AVAILABILITY_EPOCH","registry_count":1,"rejection_reasons":["AVAILABILITY_EPOCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AVAILABILITY-EXPIRED":{"authority_count":1,"direction_mask":3,"filter_index":25,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":100000,"mutation_op":"replace","mutation_path":["registry",0,"availability_expires_at_ms"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AVAILABILITY_EXPIRED","registry_count":1,"rejection_reasons":["AVAILABILITY_EXPIRED"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-AVAILABILITY-STATE":{"authority_count":1,"direction_mask":3,"filter_index":24,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":0,"mutation_op":"replace","mutation_path":["registry",0,"availability_state"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"AVAILABILITY_STATE","registry_count":1,"rejection_reasons":["AVAILABILITY_STATE"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-BOUND-REQUIRED-ABSENT":{"authority_count":1,"authority_mode":"BOUND_REQUIRED","authority_state":"ABSENT","direction_mask":3,"filter_index":26,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"BOUND_REQUIRED","mutation_op":"replace","mutation_path":["policies",0,"authority_mode"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"BOUND_REQUIRED_ABSENT","registry_count":1,"rejection_reasons":["BOUND_REQUIRED_ABSENT"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-CAPABILITY-MISSING":{"authority_count":1,"direction_mask":3,"filter_index":12,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":109,"mutation_op":"replace","mutation_path":["registry",0,"capability_flags"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"CAPABILITY_MISSING","registry_count":1,"rejection_reasons":["CAPABILITY_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-COST-CLASS":{"authority_count":1,"cost_class":51,"direction_mask":3,"filter_index":8,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":51,"mutation_op":"replace","mutation_path":["registry",0,"cost_class"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"COST_CLASS","registry_count":1,"rejection_reasons":["COST_CLASS"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-CUSTODY-MISSING":{"authority_count":1,"direction_mask":3,"filter_index":15,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":79,"mutation_op":"replace","mutation_path":["registry",0,"capability_flags"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"CUSTODY_MISSING","registry_count":1,"rejection_reasons":["CUSTODY_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-DEADLINE-GUARD":{"authority_count":1,"direction_mask":3,"filter_index":9,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":100099,"mutation_op":"replace","mutation_path":["query","deadline_ms"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"DEADLINE_GUARD","registry_count":1,"rejection_reasons":["DEADLINE_GUARD"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-DIRECTION-MISMATCH":{"authority_count":1,"direction_mask":2,"filter_index":1,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":2,"mutation_op":"replace","mutation_path":["registry",0,"direction_mask"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"DIRECTION_MISMATCH","registry_count":1,"rejection_reasons":["DIRECTION_MISMATCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-ENERGY-SLEEP-CAPABILITY-MISSING":{"authority_count":1,"direction_mask":3,"filter_index":13,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":110,"mutation_op":"replace","mutation_path":["registry",0,"capability_flags"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"ENERGY_SLEEP_CAPABILITY_MISSING","registry_count":1,"rejection_reasons":["ENERGY_SLEEP_CAPABILITY_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-EVIDENCE-MISSING":{"authority_count":1,"direction_mask":3,"filter_index":16,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":47,"mutation_op":"replace","mutation_path":["registry",0,"capability_flags"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"EVIDENCE_MISSING","registry_count":1,"rejection_reasons":["EVIDENCE_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-HARD-FILTER-PRECEDENCE":{"authority_count":1,"direction_mask":2,"filter_index":0,"lifecycle":"DRAINING","maximum_packet_bytes":587,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":586,"policy_count":1,"primary_rejection":"LIFECYCLE_DRAINING","registry_count":1,"rejection_reasons":["LIFECYCLE_DRAINING","DIRECTION_MISMATCH","STRUCTURAL_LENGTH_FLOOR","PACKET_MINIMUM","SECURITY_MISSING"],"resolution":"NO_ELIGIBLE_PATH","security_capability_flags":0,"selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-LATENCY-CLASS":{"authority_count":1,"direction_mask":3,"filter_index":7,"latency_class":51,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":51,"mutation_op":"replace","mutation_path":["registry",0,"latency_class"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"LATENCY_CLASS","registry_count":1,"rejection_reasons":["LATENCY_CLASS"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-LIFECYCLE-DRAINING":{"authority_count":1,"direction_mask":3,"filter_index":0,"lifecycle":"DRAINING","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"DRAINING","mutation_op":"replace","mutation_path":["registry",0,"lifecycle"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"LIFECYCLE_DRAINING","registry_count":1,"rejection_reasons":["LIFECYCLE_DRAINING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-META-OUTER-UNAVAILABLE":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":0,"mutation_op":"replace","mutation_path":["meta","outer_available"],"outer_available":0,"packet_bytes":587,"policy_count":1,"primary_rejection":"META_OUTER_UNAVAILABLE","registry_count":1,"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-MTU-BASELINE":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":587,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":1,"resolution":"SELECTED","selected_instance_id_hex":"6162636465666768696a6b6c6d6e6f70","transfer_bytes":587},"FABRIC-SELECT-PACKET-MINIMUM":{"authority_count":1,"direction_mask":3,"filter_index":4,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":600,"mutation_new":600,"mutation_op":"replace","mutation_path":["policies",0,"minimum_packet_bytes"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"PACKET_MINIMUM","registry_count":1,"rejection_reasons":["PACKET_MINIMUM"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-PACKET-MTU":{"authority_count":1,"direction_mask":3,"filter_index":5,"lifecycle":"ACTIVE","maximum_packet_bytes":587,"minimum_packet_bytes":587,"mutation_new":588,"mutation_op":"replace","mutation_path":["query","packet_bytes"],"outer_available":1,"packet_bytes":588,"policy_count":1,"primary_rejection":"PACKET_MTU","registry_count":1,"rejection_reasons":["PACKET_MTU"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-PEER-NFL1-UNSUPPORTED":{"authority_count":1,"direction_mask":3,"filter_index":17,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":2,"mutation_op":"replace","mutation_path":["registry",0,"peer_nfl1_version"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"PEER_NFL1","registry_count":1,"rejection_reasons":["PEER_NFL1"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-POLICY-AMBIGUOUS":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_op":"append","mutation_path":["policies"],"outer_available":1,"packet_bytes":587,"policy_count":2,"primary_rejection":"POLICY_AMBIGUOUS","registry_count":1,"resolution":"CORRUPT","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-POLICY-NO-MATCH":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"67da0ab19cf2bab070be081de4a661d9e7415cb0e151e110d9f7490ff1fca07a","mutation_op":"replace","mutation_path":["query","service_identity_digest_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"POLICY_NO_MATCH","registry_count":1,"resolution":"NO_POLICY","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-POLICY-REVISION-GAP":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":[1,3],"mutation_op":"replace","mutation_path":["policies",0,"revision_chain"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"POLICY_REVISION_GAP","registry_count":1,"resolution":"CORRUPT","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-REGISTRY-JOIN-MISSING":{"authority_count":1,"direction_mask":null,"filter_index":null,"lifecycle":null,"maximum_packet_bytes":null,"minimum_packet_bytes":587,"mutation_op":"remove","mutation_path":["registry"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"REGISTRY_JOIN_MISSING","registry_count":0,"rejection_reasons":["REGISTRY_JOIN_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-RESERVATION-CAPACITY":{"authority_count":1,"direction_mask":3,"filter_index":11,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_op":"append","mutation_path":["active_attempts"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"RESERVATION_CAPACITY","registry_count":1,"rejection_reasons":["RESERVATION_CAPACITY"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-RETRY-LIFETIME-CLOCK-EPOCH":{"authority_count":1,"direction_mask":3,"filter_index":10,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":"a2a3a4a5a6a7a8a9aaabacadaeafb0b1","mutation_op":"replace","mutation_path":["query","admission_clock_epoch_id_hex"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"RETRY_LIFETIME_CLOCK_EPOCH","registry_count":1,"rejection_reasons":["RETRY_LIFETIME_CLOCK_EPOCH"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-RF-MAPPING-BASELINE":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","link_kind":"RF","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":1,"resolution":"SELECTED","selected_instance_id_hex":"6162636465666768696a6b6c6d6e6f70","transfer_bytes":587},"FABRIC-SELECT-RF-MAPPING-UNSUPPORTED":{"authority_count":1,"direction_mask":3,"filter_index":30,"lifecycle":"ACTIVE","link_kind":"RF","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":false,"mutation_op":"replace","mutation_path":["query","rf_mapping_accepted"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"RF_MAPPING_UNSUPPORTED","registry_count":1,"rejection_reasons":["RF_MAPPING_UNSUPPORTED"],"resolution":"NO_ELIGIBLE_PATH","rf_mapping_accepted":false,"rf_permit_valid":true,"selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-RF-NO-PERMIT":{"authority_count":1,"direction_mask":3,"filter_index":29,"lifecycle":"ACTIVE","link_kind":"RF","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":false,"mutation_op":"replace","mutation_path":["query","rf_permit_valid"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"RF_PERMIT","registry_count":1,"rejection_reasons":["RF_PERMIT"],"resolution":"NO_ELIGIBLE_PATH","rf_mapping_accepted":true,"rf_permit_valid":false,"selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-SAME-KIND-TWO-INSTANCES":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":2,"resolution":"SELECTED","selected_instance_id_hex":"6162636465666768696a6b6c6d6e6f70","transfer_bytes":587},"FABRIC-SELECT-SECURITY-MISSING":{"authority_count":1,"direction_mask":3,"filter_index":14,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":7,"mutation_op":"replace","mutation_path":["registry",0,"security_capability_flags"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"SECURITY_MISSING","registry_count":1,"rejection_reasons":["SECURITY_MISSING"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-SOURCE-RUNTIME-ENDPOINT":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":1,"resolution":"SELECTED","scope_selector":"SOURCE_RUNTIME","selected_instance_id_hex":"6162636465666768696a6b6c6d6e6f70","transfer_bytes":587},"FABRIC-SELECT-STABLE-ID-TIEBREAK":{"authority_count":1,"direction_mask":3,"filter_index":null,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":null,"registry_count":2,"resolution":"SELECTED","selected_instance_id_hex":"0102030405060708090a0b0c0d0e0f10","transfer_bytes":587},"FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING":{"authority_count":1,"direction_mask":3,"filter_index":3,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":1926,"mutation_op":"replace","mutation_path":["query","packet_bytes"],"outer_available":1,"packet_bytes":1926,"policy_count":1,"primary_rejection":"STRUCTURAL_LENGTH_CEILING","registry_count":1,"rejection_reasons":["STRUCTURAL_LENGTH_CEILING","PACKET_MTU"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR":{"authority_count":1,"direction_mask":3,"filter_index":2,"lifecycle":"ACTIVE","maximum_packet_bytes":1925,"minimum_packet_bytes":587,"mutation_new":586,"mutation_op":"replace","mutation_path":["query","packet_bytes"],"outer_available":1,"packet_bytes":586,"policy_count":1,"primary_rejection":"STRUCTURAL_LENGTH_FLOOR","registry_count":1,"rejection_reasons":["STRUCTURAL_LENGTH_FLOOR","PACKET_MINIMUM"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":587},"FABRIC-SELECT-TRANSFER-MTU":{"authority_count":1,"direction_mask":3,"filter_index":6,"lifecycle":"ACTIVE","maximum_packet_bytes":587,"minimum_packet_bytes":587,"mutation_new":588,"mutation_op":"replace","mutation_path":["query","transfer_bytes"],"outer_available":1,"packet_bytes":587,"policy_count":1,"primary_rejection":"TRANSFER_MTU","registry_count":1,"rejection_reasons":["TRANSFER_MTU"],"resolution":"NO_ELIGIBLE_PATH","selected_instance_id_hex":null,"transfer_bytes":588}};


function assertSelectionSemantics(id,row){
  const exp=selectionSemantics[id];
  if (!exp) fail(id+': missing selectionSemantics');
  const m=row.model, inp=row.inputs, q=inp.query;
  if (m.primary_rejection!==exp.primary_rejection) fail(id+': primary_rejection semantic');
  if (m.resolution!==exp.resolution) fail(id+': resolution semantic');
  if (m.selected_instance_id_hex!==exp.selected_instance_id_hex)
    fail(id+': selected instance semantic');
  if (q.packet_bytes!==exp.packet_bytes) fail(id+': packet_bytes');
  if (q.transfer_bytes!==exp.transfer_bytes) fail(id+': transfer_bytes');
  if (inp.meta.outer_available!==exp.outer_available) fail(id+': outer_available');
  if (inp.authorities.length!==exp.authority_count) fail(id+': authority_count');
  if (inp.registry.length!==exp.registry_count) fail(id+': registry_count');
  if (inp.policies.length!==exp.policy_count) fail(id+': policy_count');
  if (exp.minimum_packet_bytes!=null
      && inp.policies[0].minimum_packet_bytes!==exp.minimum_packet_bytes)
    fail(id+': minimum_packet_bytes');
  if (exp.maximum_packet_bytes!=null
      && inp.registry[0].maximum_packet_bytes!==exp.maximum_packet_bytes)
    fail(id+': maximum_packet_bytes');
  if (exp.lifecycle!=null && inp.registry[0].lifecycle!==exp.lifecycle)
    fail(id+': lifecycle');
  if (exp.direction_mask!=null && inp.registry[0].direction_mask!==exp.direction_mask)
    fail(id+': direction_mask');
  if (exp.filter_index!=null) {
    if (hardFilterOrder[exp.filter_index]!==exp.primary_rejection)
      fail(id+': filter_index order');
    if (m.primary_rejection!==hardFilterOrder[exp.filter_index])
      fail(id+': primary vs filter_index');
  }
  if (exp.rejection_reasons) {
    const reasons=(m.evaluated && m.evaluated[0] && m.evaluated[0].rejection_reasons)||[];
    if (stable(reasons)!==stable(exp.rejection_reasons))
      fail(id+': rejection_reasons order');
    if (exp.filter_index!=null && reasons.length && reasons[0]!==exp.primary_rejection)
      fail(id+': primary is first reason');
  }
  if (exp.mutation_op==='replace') {
    const mut=row.mutation||{};
    if (mut.operation!=='replace') fail(id+': mutation op');
    if (stable(mut.path)!==stable(exp.mutation_path)) fail(id+': mutation path');
    if (stable(mut.new)!==stable(exp.mutation_new)) fail(id+': mutation new');
  } else if (exp.mutation_op==='append' || exp.mutation_op==='remove') {
    const mut=row.mutation||{};
    if (mut.operation!==exp.mutation_op) fail(id+': mutation op');
    if (stable(mut.path)!==stable(exp.mutation_path)) fail(id+': mutation path');
  }
  if (exp.scope_selector!=null
      && inp.policies[0].scope_selector!==exp.scope_selector)
    fail(id+': scope_selector');
  if (exp.authority_mode!=null
      && inp.policies[0].authority_mode!==exp.authority_mode)
    fail(id+': authority_mode');
  if (exp.authority_state!=null
      && inp.authorities[0].authority_state!==exp.authority_state)
    fail(id+': authority_state');
  if (exp.link_kind!=null && inp.registry[0].link_kind!==exp.link_kind)
    fail(id+': link_kind');
  if (exp.rf_mapping_accepted!=null
      && q.rf_mapping_accepted!==exp.rf_mapping_accepted)
    fail(id+': rf_mapping_accepted');
  if (exp.rf_permit_valid!=null && q.rf_permit_valid!==exp.rf_permit_valid)
    fail(id+': rf_permit_valid');
  if (exp.latency_class!=null && inp.registry[0].latency_class!==exp.latency_class)
    fail(id+': latency_class');
  if (exp.cost_class!=null && inp.registry[0].cost_class!==exp.cost_class)
    fail(id+': cost_class');
  if (exp.security_capability_flags!=null
      && inp.registry[0].security_capability_flags!==exp.security_capability_flags)
    fail(id+': security_capability_flags');
  if (exp.authority_binding_ids) {
    const bindings=[...inp.authorities.map(a=>a.binding_id_hex)].sort();
    if (stable(bindings)!==stable(exp.authority_binding_ids))
      fail(id+': authority binding identity set');
    if (new Set(bindings).size!==exp.authority_count)
      fail(id+': distinct authority bindings');
    const pids=inp.authorities.map(a=>a.policy_id_hex);
    if (new Set(pids).size!==1)
      fail(id+': ambiguous authorities share policy identity');
  }
  if (id==='FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR') {
    if (q.packet_bytes!==586) fail(id+': floor boundary 586');
    if (!(q.packet_bytes<587)) fail(id+': below structural min');
  }
  if (id==='FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING') {
    if (q.packet_bytes!==1926) fail(id+': ceiling boundary 1926');
    if (!(q.packet_bytes>1925)) fail(id+': above structural max');
  }
  if (id==='FABRIC-SELECT-PACKET-MINIMUM') {
    if (q.packet_bytes!==587) fail(id+': structural-legal packet');
    if (inp.policies[0].minimum_packet_bytes!==600) fail(id+': policy min 600');
    if (!(q.packet_bytes>=587)) fail(id+': not structural floor');
  }
}
if (Object.keys(selectionSemantics).length!==46)
  fail('selectionSemantics must cover exact 46 actual IDs');
for (const id of actualSelectionIds)
  if (!selectionSemantics[id]) fail(id+': missing selectionSemantics entry');

for (const [id,row] of selectionRows) {
  const mutation=row.mutation;
  const baselineId=mutation?(mutation.baseline_id||'FABRIC-SELECT-ACTUAL-JOIN-BASELINE'):id;
  const baseline=selectionRows.get(baselineId).inputs;
  const projected=projectSelection(
    row.inputs,baseline.query,baseline.active_attempts,id
  );
  if (mutation) applyMutation(projected,mutation);
  if (stable(normalizedInputs(projected))!==stable(normalizedInputs(row.inputs)))
    fail(id+': semantic inputs diverge from durable projection');
  const [selected,rejection]=selectionDecision(projected);
  if (selected!==row.model.selected_instance_id_hex) fail(id+': durable selected');
  if (rejection!==row.model.primary_rejection) fail(id+': durable rejection');
  assertSelectionSemantics(id,row);
  if (mutation) {
    const rebuilt=clone(baseline);
    applyMutation(rebuilt,mutation);
    if (stable(rebuilt)!==stable(row.inputs)) fail(id+': single mutation');
  }
}
const fbaCases={
  'FABRIC-FBA-PREPARED-TO-LINK-RETAINED':[[1,2],
    {cause:'PROVIDER_RETAINED',outer_result:'OK_SEND_ACCEPTED',
     permit_claim_after:1,permit_claim_before:1}],
  'FABRIC-FBA-PREPARED-TO-RETRYABLE':[[1,3],
    {cause:'PROVIDER_WOULD_BLOCK',outer_result:'WOULD_BLOCK',
     permit_claim_after:0,permit_claim_before:1,release_tentative_resources:1}],
  'FABRIC-FBA-RETRYABLE-TO-PREPARED':[[3,1],
    {cause:'EXACT_RETRY_BEFORE_DURABLE_EXPIRY',fresh_permit_pair:1,
     permit_claim_after:1,permit_claim_before:0,provider_start_calls_after_commit:1,
     registry_authority_snapshot_match:1,retry_expires_at_ms:200000,retry_now_ms:199999}],
  'FABRIC-FBA-PREPARED-TO-CLOSED-HARD-RACE':[[1,4],
    {cause:'PRE_START_HARD_GATE_CHANGED',outer_result:'UNAVAILABLE_OR_DENIED',
     permit_claim_after:0,permit_claim_before:0,provider_start_calls:0}],
  'FABRIC-FBA-PREPARED-TO-CLOSED-RELEASE':[[1,4],
    {cause:'RUNTIME_DISPATCH_RELEASE_BEFORE_START',followup_transition:'CLOSED_TO_DRAINED',
     permit_claim_after:0,permit_claim_before:0,provider_start_calls:0}],
  'FABRIC-FBA-LINK-RETAINED-TO-CLOSED':[[2,4],
    {automatic_duplicate:0,cause:'PROVIDER_TERMINAL',
     permit_claim_after:1,permit_claim_before:1}],
  'FABRIC-FBA-PREPARED-TO-FENCED-RESTART':[[1,5],
    {automatic_duplicate:0,cause:'RESTART_VOLATILE_QUEUE_LOST',
     permit_claim_after:0,permit_claim_before:0,provider_start_calls:0}],
  'FABRIC-FBA-LINK-RETAINED-TO-FENCED-RESTART':[[2,5],
    {automatic_duplicate:0,cause:'RESTART_PROVIDER_TOKEN_LOST',
     permit_claim_after:1,permit_claim_before:1,provider_start_calls:0}],
  'FABRIC-FBA-RETRYABLE-RESTART-BEFORE-EXPIRY':[[3,3],
    {cause:'RESTART_DURABLE_RETRY_LIFETIME_VALID',provider_start_calls:0,
     permit_claim_after:0,permit_claim_before:0,retry_expires_at_ms:200000,
     retry_now_ms:199999,storage_mutations:0}],
  'FABRIC-FBA-RETRYABLE-RESTART-AT-EXPIRY':[[3,4],
    {cause:'RESTART_DURABLE_RETRY_LIFETIME_EXPIRED',provider_start_calls:0,
     permit_claim_after:0,permit_claim_before:0,retry_expires_at_ms:200000,
     retry_now_ms:200000}],
  'FABRIC-FBA-CLOSED-TO-DRAINED':[[4,6],
    {cause:'RUNTIME_DISPATCH_RELEASE',permit_claim_after:1,
     permit_claim_before:1,runtime_terminal_revision:41}],
  'FABRIC-FBA-FENCED-TO-DRAINED':[[5,6],
    {cause:'RUNTIME_DISPATCH_RELEASE_AFTER_RECONCILE',permit_claim_after:1,
     permit_claim_before:1,runtime_terminal_revision:41}],
};
const expectedFbaIds=Object.keys(fbaCases);
if (expectedFbaIds.length!==12)
  fail('FBA state transition: internal exact 12');
if (!Array.isArray(doc.fba_state_transition_vectors)
    || doc.fba_state_transition_vectors.length!==expectedFbaIds.length)
  fail('FBA state transition: exact vector count');
const rawFbaIds=doc.fba_state_transition_vectors.map((row,index)=>{
  if (!row || typeof row!=='object' || Array.isArray(row)
      || typeof row.id!=='string')
    fail('FBA state transition['+index+']: vector/object ID');
  return row.id;
});
if (new Set(rawFbaIds).size!==rawFbaIds.length)
  fail('FBA state transition: duplicate vector ID');
const expectedFbaIdSet=new Set(expectedFbaIds);
if (rawFbaIds.some(id=>!expectedFbaIdSet.has(id))
    || expectedFbaIds.some(id=>!rawFbaIds.includes(id)))
  fail('FBA state transition: unknown/missing vector ID');
for (const row of doc.fba_state_transition_vectors) {
  const [states,expectedMeta]=fbaCases[row.id]||fail(row.id+': unknown FBA case');
  if (row.old_rows.length!==1 || row.new_rows.length!==1) fail(row.id+': row count');
  const old=check(row.old_rows[0].key_hex,row.old_rows[0].value_hex,row.id+':old');
  const next=check(row.new_rows[0].key_hex,row.new_rows[0].value_hex,row.id+':new');
  if (!old.k.equals(next.k)) fail(row.id+': key changed');
  const on=Buffer.from(old.v), nn=Buffer.from(next.v);
  for (const v of [on,nn]) {
    v.fill(0,12,24); v.fill(0,64,68); v.fill(0,676,684);
    v.fill(0,708,712);
    if (row.fresh_permit_pair===1) v.fill(0,684,708);
  }
  if (!on.equals(nn)) fail(row.id+': immutable FBA changed');
  if (u32(old.v,64)!==states[0] || u32(next.v,64)!==states[1])
    fail(row.id+': case state transition');
  if (u32(old.v,708)!==row.permit_claim_before
      || u32(next.v,708)!==row.permit_claim_after)
    fail(row.id+': permit claim transition');
  if (!old.v.subarray(620,636).equals(next.v.subarray(620,636)))
    fail(row.id+': permit clock epoch immutable');
  if (row.fresh_permit_pair===1) {
    if (old.v.subarray(684,700).equals(next.v.subarray(684,700)))
      fail(row.id+': fresh permit ID');
    if (u64(old.v,700)===0n || u64(next.v,700)===0n)
      fail(row.id+': fresh permit expiry');
  } else if (!old.v.subarray(684,708).equals(next.v.subarray(684,708))) {
    fail(row.id+': permit pair immutable');
  }
  const meta={};
  for (const [key,value] of Object.entries(row))
    if (!['id','old_rows','new_rows'].includes(key)) meta[key]=value;
  if (stable(meta)!==stable(expectedMeta)) fail(row.id+': case outcome/side effects');
  if (row.storage_mutations===0) {
    if (!old.v.equals(next.v)) fail(row.id+': no-op bytes');
  } else if (u64(next.v,12)!==u64(old.v,12)+1n) fail(row.id+': revision not exact +1');
  if ('retry_expires_at_ms' in row) {
    if (Number(u64(old.v,636))!==row.retry_expires_at_ms
        || Number(u64(next.v,636))!==row.retry_expires_at_ms)
      fail(row.id+': durable retry expiry');
    const before=row.id.endsWith('BEFORE-EXPIRY') || row.id.endsWith('TO-PREPARED');
    if (before ? !(row.retry_now_ms<row.retry_expires_at_ms)
               : !(row.retry_now_ms>=row.retry_expires_at_ms))
      fail(row.id+': retry time relation');
  }
  const terminal=row.runtime_terminal_revision||0;
  if (Number(u64(next.v,676))!==terminal) fail(row.id+': terminal revision');
  if (terminal && u64(old.v,676)!==0n) fail(row.id+': old terminal revision');
}
const freshCases={
  'FABRIC-FRESH-READ-ONLY-ZERO-ROWS':
    {phase:'READ_ONLY_SCAN',result:'ROLLBACK_OK_THEN_OPEN_READ_WRITE'},
  'FABRIC-FRESH-READ-WRITE-ZERO-ROWS':
    {phase:'READ_WRITE_RESCAN',result:'PUT_CANONICAL_FBM1_REVISION_1_FULL'},
  'FABRIC-FRESH-READ-WRITE-RACE':
    {phase:'READ_WRITE_RESCAN',result:'CORRUPT_MUTATION_ZERO'},
  'FABRIC-FRESH-COMMIT-OK-REOPEN-EXISTING':
    {phase:'REOPEN_READ_ONLY_EXISTING_SCAN',commit_result:'OK',
     classification:'EXISTING',registry_publish:1},
  'FABRIC-EXISTING-WITHOUT-META':
    {phase:'READ_ONLY_EXISTING_SCAN',classification:'CORRUPT',registry_publish:0},
  'FABRIC-EXISTING-DUPLICATE-KEY':
    {phase:'READ_ONLY_EXISTING_SCAN',classification:'CORRUPT',registry_publish:0},
  'FABRIC-EXISTING-OUT-OF-ORDER':
    {phase:'READ_ONLY_EXISTING_SCAN',classification:'CORRUPT',registry_publish:0},
  'FABRIC-EXISTING-COUNT-OVERFLOW':
    {phase:'READ_ONLY_EXISTING_SCAN',overflow_prefix:'FBP1',observed_count:65,
     maximum_count:64,classification:'CORRUPT',registry_publish:0},
  'FABRIC-FRESH-COMMIT-UNKNOWN-ABSENT':
    {phase:'REOPEN_READ_CLASSIFY',classification:'ABSENT',
     create_result:'COMMIT_UNKNOWN_NO_PUBLISH'},
  'FABRIC-FRESH-COMMIT-UNKNOWN-NEW':
    {phase:'REOPEN_READ_CLASSIFY',classification:'NEW',
     create_result:'COMMIT_UNKNOWN_NO_PUBLISH'},
  'FABRIC-FRESH-COMMIT-UNKNOWN-THIRD':
    {phase:'REOPEN_READ_CLASSIFY',classification:'CORRUPT',
     create_result:'COMMIT_UNKNOWN_NO_PUBLISH'},
};
const expectedFreshIds=Object.keys(freshCases);
if (expectedFreshIds.length!==11)
  fail('fresh adoption: internal exact 11');
if (!Array.isArray(doc.fresh_adoption_vectors)
    || doc.fresh_adoption_vectors.length!==expectedFreshIds.length)
  fail('fresh adoption: exact vector count');
const rawFreshIds=doc.fresh_adoption_vectors.map((row,index)=>{
  if (!row || typeof row!=='object' || Array.isArray(row)
      || typeof row.id!=='string')
    fail('fresh adoption['+index+']: vector/object ID');
  return row.id;
});
if (new Set(rawFreshIds).size!==rawFreshIds.length)
  fail('fresh adoption: duplicate vector ID');
const expectedFreshIdSet=new Set(expectedFreshIds);
if (rawFreshIds.some(id=>!expectedFreshIdSet.has(id))
    || expectedFreshIds.some(id=>!rawFreshIds.includes(id)))
  fail('fresh adoption: unknown/missing vector ID');
const canonicalMeta=doc.storage_records.find(r=>r.id==='FABRIC-STORE-META-1');
const canonicalFbm={key_hex:canonicalMeta.key_hex,value_hex:canonicalMeta.value_hex};
const limits={FBM1:1,FBR1:16,FBP1:64,FBC1:64,FBA1:64,FBT1:64};
for (const row of doc.fresh_adoption_vectors) {
  const expected=freshCases[row.id]||fail(row.id+': unknown fresh case'), meta={};
  for (const [key,value] of Object.entries(row))
    if (!['id','old_rows','new_rows','observed_rows','put_rows'].includes(key))
      meta[key]=value;
  if (stable(meta)!==stable(expected)) fail(row.id+': case outcome');
  for (const field of ['old_rows','new_rows','observed_rows','put_rows'])
    for (const item of row[field]||[]) check(item.key_hex,item.value_hex,row.id+':'+field);
  const observed=row.observed_rows||[];
  if (row.phase==='READ_ONLY_SCAN') {
    if (observed.length) fail(row.id+': fresh read-only zero');
  } else if (row.phase==='READ_WRITE_RESCAN') {
    if (row.id==='FABRIC-FRESH-READ-WRITE-ZERO-ROWS') {
      if (observed.length || stable(row.put_rows)!==stable([canonicalFbm]))
        fail(row.id+': canonical FBM1 put');
    } else if (!observed.length || (row.put_rows||[]).length)
      fail(row.id+': race mutation zero');
  } else if (row.phase==='REOPEN_READ_CLASSIFY') {
    const old=row.old_rows||[], next=row.new_rows||[];
    const classification=stable(observed)===stable(old) && !old.length?'ABSENT'
      :stable(observed)===stable(next)?'NEW':'CORRUPT';
    if (row.classification!==classification) fail(row.id+': fresh reopen classification');
    if (row.create_result!=='COMMIT_UNKNOWN_NO_PUBLISH') fail(row.id+': fresh reopen result');
  } else {
    const keys=observed.map(item=>Buffer.from(item.key_hex,'hex'));
    const strict=keys.every((key,i)=>!i || Buffer.compare(keys[i-1],key)<0);
    const counts={};
    for (const magic of Object.keys(limits))
      counts[magic]=keys.filter(key=>key.subarray(0,4).toString('ascii')===magic).length;
    const valid=strict && counts.FBM1===1
      && Object.keys(limits).every(magic=>counts[magic]<=limits[magic]);
    if (row.classification!==(valid?'EXISTING':'CORRUPT'))
      fail(row.id+': existing reopen classification');
    if (row.registry_publish!==Number(valid)) fail(row.id+': reopen publish');
  }
}
for (const section of ['fba_state_transition_vectors','fba_commit_unknown_vectors',
                        'fresh_adoption_vectors','commit_unknown_matrix']) {
  for (const vector of doc[section] || []) {
    for (const field of ['old_rows','new_rows','observed_rows','put_rows']) {
      for (const r of vector[field] || []) check(r.key_hex,r.value_hex,vector.id+':'+field);
    }
  }
}
console.log('fabric bearer Node durable oracle: OK');
"""


def run_node(path: Path) -> None:
    node = shutil.which("node")
    require(node is not None, "Node.js is required for cross-language gate")
    result = subprocess.run(
        [node, "-e", NODE_ORACLE, str(path)],
        check=False,
        text=True,
        capture_output=True,
    )
    require(
        result.returncode == 0,
        "Node durable oracle failed: " + (result.stderr or result.stdout).strip(),
    )


def check_path(path: Path, with_node: bool = True) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    validate_python(document)
    if with_node:
        run_node(path)


def self_test() -> None:
    subprocess.run(
        [sys.executable, str(GENERATOR), "--check"], check=True
    )
    check_path(VECTOR)
    original = json.loads(VECTOR.read_text(encoding="utf-8"))
    mutations = []

    bad_crc = copy.deepcopy(original)
    value = bytearray.fromhex(bad_crc["storage_records"][0]["value_hex"])
    value[-1] ^= 1
    bad_crc["storage_records"][0]["value_hex"] = value.hex()
    mutations.append(("record-byte", bad_crc))

    key_identity_mutations: list[tuple[str, dict[str, Any]]] = []
    for label, vector_id in (
        ("FBR-key-identity", "FABRIC-STORE-REGISTRY-1"),
        ("FBP-key-identity", "FABRIC-STORE-POLICY-1"),
        (
            "FBC-key-identity",
            "FABRIC-STORE-AUTHORITY-TARGET-RUNTIME",
        ),
        ("FBT-key-identity", "FABRIC-STORE-TRIGGER-1"),
    ):
        candidate = copy.deepcopy(original)
        record = next(
            row
            for row in candidate["storage_records"]
            if row["id"] == vector_id
        )
        key = bytearray.fromhex(record["key_hex"])
        key[-1] ^= 1
        value = bytes.fromhex(record["value_hex"])
        record["key_hex"] = key.hex()
        record["sha256_hex"] = hashlib.sha256(key + value).hexdigest()
        key_identity_mutations.append((label, candidate))
        mutations.append((label, candidate))

    bad_selection = copy.deepcopy(original)
    bad_selection["selection_vectors"][0]["model"][
        "selected_instance_id_hex"
    ] = None
    mutations.append(("selection-decision", bad_selection))

    # Obsolete CU totals from docs/06 drift must fail closed.
    bad_committed_cu = copy.deepcopy(original)
    bad_committed_cu["constants"]["durable_storage_cu_bytes_max"] = 136148
    mutations.append(("obsolete-committed-cu-136148", bad_committed_cu))
    bad_staging_cu = copy.deepcopy(original)
    bad_staging_cu["constants"][
        "full_staging_storage_cu_bytes_required"
    ] = 272296
    mutations.append(("obsolete-full-staging-cu-272296", bad_staging_cu))

    selection_inventory_mutations: list[tuple[str, dict[str, Any]]] = []
    missing_selection = copy.deepcopy(original)
    missing_selection["selection_vectors"] = [
        row
        for row in missing_selection["selection_vectors"]
        if row["id"] != "FABRIC-SELECT-LATENCY-CLASS"
    ]
    selection_inventory_mutations.append(
        ("selection-inventory-missing-nonrequired", missing_selection)
    )

    unknown_selection = copy.deepcopy(original)
    unknown_row = copy.deepcopy(
        next(
            row
            for row in unknown_selection["selection_vectors"]
            if row["id"] == "FABRIC-SELECT-ACTUAL-JOIN-BASELINE"
        )
    )
    unknown_row["id"] = "FABRIC-SELECT-VALID-UNKNOWN"
    unknown_selection["selection_vectors"].append(unknown_row)
    selection_inventory_mutations.append(
        ("selection-inventory-valid-unknown", unknown_selection)
    )

    duplicate_selection = copy.deepcopy(original)
    duplicate_selection["selection_vectors"].append(
        copy.deepcopy(
            next(
                row
                for row in duplicate_selection["selection_vectors"]
                if row["id"] == "FABRIC-SELECT-LATENCY-CLASS"
            )
        )
    )
    selection_inventory_mutations.append(
        ("selection-inventory-duplicate", duplicate_selection)
    )

    substituted_selection = copy.deepcopy(original)
    substitute_row = next(
        row
        for row in substituted_selection["selection_vectors"]
        if row["id"] == "FABRIC-SELECT-LATENCY-CLASS"
    )
    substitute_row["id"] = "FABRIC-SELECT-VALID-SUBSTITUTE"
    selection_inventory_mutations.append(
        ("selection-inventory-substitute", substituted_selection)
    )
    mutations.extend(selection_inventory_mutations)

    # Full-row ID-preserving substitutions must fail independent semantic checks.
    critical_selection_ids = list(ACTUAL_SELECTION_IDS)
    baseline_row = next(
        row
        for row in original["selection_vectors"]
        if row["id"] == "FABRIC-SELECT-ACTUAL-JOIN-BASELINE"
    )
    for target_id in critical_selection_ids:
        if target_id == "FABRIC-SELECT-ACTUAL-JOIN-BASELINE":
            # Substitute baseline with a rejection body while keeping baseline ID.
            donor = next(
                row
                for row in original["selection_vectors"]
                if row["id"] == "FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR"
            )
        else:
            donor = baseline_row
        substituted = copy.deepcopy(original)
        for index, row in enumerate(substituted["selection_vectors"]):
            if row["id"] == target_id:
                forged = copy.deepcopy(donor)
                forged["id"] = target_id
                substituted["selection_vectors"][index] = forged
                break
        else:
            raise GateError(f"self-test missing selection id {target_id}")
        mutations.append(
            (f"selection-full-row-substitute-{target_id}", substituted)
        )


    bad_pre_retain_race = copy.deepcopy(original)
    race = next(
        row
        for row in bad_pre_retain_race["selection_vectors"]
        if row["id"] == "FABRIC-SELECT-AVAILABILITY-EPOCH-RACE"
    )
    race["provider_start_calls"] = 1
    mutations.append(
        ("selection-pre-retain-race-side-effect", bad_pre_retain_race)
    )

    bad_post_retain_race = copy.deepcopy(original)
    race = next(
        row
        for row in bad_post_retain_race["selection_vectors"]
        if row["id"] == "FABRIC-SELECT-POST-RETAIN-EPOCH-RACE"
    )
    race["track_provider_token_to_terminal"] = 0
    mutations.append(
        ("selection-post-retain-race-side-effect", bad_post_retain_race)
    )

    bad_durable_selection = copy.deepcopy(original)
    baseline = next(
        row
        for row in bad_durable_selection["selection_vectors"]
        if row["id"] == "FABRIC-SELECT-ACTUAL-JOIN-BASELINE"
    )
    durable = baseline["inputs"]["durable_rows"]["FBR1"]
    value = bytearray.fromhex(durable["value_hex"])
    value[272:276] = struct.pack(">I", 586)
    durable["value_hex"] = repair_record_crc(bytes(value)).hex()
    mutations.append(("durable-selection-divergence", bad_durable_selection))

    bad_fba_side_effect = copy.deepcopy(original)
    transition = next(
        row
        for row in bad_fba_side_effect["fba_state_transition_vectors"]
        if row["id"] == "FABRIC-FBA-PREPARED-TO-FENCED-RESTART"
    )
    transition["provider_start_calls"] = 1
    mutations.append(("FBA-restart-side-effect", bad_fba_side_effect))

    bad_fba_time = copy.deepcopy(original)
    transition = next(
        row
        for row in bad_fba_time["fba_state_transition_vectors"]
        if row["id"] == "FABRIC-FBA-RETRYABLE-RESTART-BEFORE-EXPIRY"
    )
    transition["retry_now_ms"] = transition["retry_expires_at_ms"]
    mutations.append(("FBA-exclusive-expiry", bad_fba_time))

    fba_inventory_mutations: list[tuple[str, dict[str, Any]]] = []
    missing_fba = copy.deepcopy(original)
    missing_fba["fba_state_transition_vectors"].pop()
    fba_inventory_mutations.append(("FBA-inventory-missing", missing_fba))

    duplicate_fba = copy.deepcopy(original)
    duplicate_fba["fba_state_transition_vectors"][-1] = copy.deepcopy(
        duplicate_fba["fba_state_transition_vectors"][0]
    )
    fba_inventory_mutations.append(("FBA-inventory-duplicate", duplicate_fba))

    unknown_fba = copy.deepcopy(original)
    unknown_fba["fba_state_transition_vectors"][-1]["id"] = (
        "FABRIC-FBA-VALID-UNKNOWN"
    )
    fba_inventory_mutations.append(("FBA-inventory-unknown", unknown_fba))
    mutations.extend(fba_inventory_mutations)

    bad_storage_enum = copy.deepcopy(original)
    enum_row = next(
        row
        for row in bad_storage_enum["storage_negative_vectors"]
        if row["id"] == "FABRIC-STORE-REGISTRY-UNKNOWN-LINK-KIND"
    )
    value = bytearray.fromhex(enum_row["value_hex"])
    value[40:44] = struct.pack(">I", 2)
    enum_row["value_hex"] = repair_record_crc(bytes(value)).hex()
    mutations.append(("storage-enum-became-known", bad_storage_enum))

    bad_nfl_enum = copy.deepcopy(original)
    enum_row = next(
        row
        for row in bad_nfl_enum["nfl1_negative_vectors"]
        if row["id"]
        == "FABRIC-NFL1-UNKNOWN-DESCRIPTOR-DIGEST-ALGORITHM"
    )
    value = bytearray.fromhex(enum_row["encoded_hex"])
    value[308:310] = struct.pack(">H", 1)
    repaired = repair_nfl1_crc(bytes(value))
    enum_row["encoded_hex"] = repaired.hex()
    enum_row["sha256_hex"] = hashlib.sha256(repaired).hexdigest()
    mutations.append(("NFL-enum-became-known", bad_nfl_enum))

    bad_nfl_boundary_expected = copy.deepcopy(original)
    boundary_row = next(
        row
        for row in bad_nfl_boundary_expected["nfl1_negative_vectors"]
        if row["id"] == "FABRIC-NFL1-STRUCTURAL-LENGTH-1926"
    )
    boundary_row["expected"] = "ACCEPT_STRUCTURAL_LENGTH_1926"
    mutations.append(
        ("NFL-structural-boundary-expectation", bad_nfl_boundary_expected)
    )

    bad_fresh_reopen = copy.deepcopy(original)
    fresh_row = next(
        row
        for row in bad_fresh_reopen["fresh_adoption_vectors"]
        if row["id"] == "FABRIC-FRESH-COMMIT-UNKNOWN-NEW"
    )
    fresh_row["classification"] = "ABSENT"
    mutations.append(("fresh-reopen-outcome", bad_fresh_reopen))

    fresh_inventory_mutations: list[tuple[str, dict[str, Any]]] = []
    missing_fresh = copy.deepcopy(original)
    missing_fresh["fresh_adoption_vectors"].pop()
    fresh_inventory_mutations.append(
        ("fresh-inventory-missing", missing_fresh)
    )

    duplicate_fresh = copy.deepcopy(original)
    duplicate_fresh["fresh_adoption_vectors"][-1] = copy.deepcopy(
        duplicate_fresh["fresh_adoption_vectors"][0]
    )
    fresh_inventory_mutations.append(
        ("fresh-inventory-duplicate", duplicate_fresh)
    )

    unknown_fresh = copy.deepcopy(original)
    unknown_fresh["fresh_adoption_vectors"][-1]["id"] = (
        "FABRIC-FRESH-VALID-UNKNOWN"
    )
    fresh_inventory_mutations.append(
        ("fresh-inventory-unknown", unknown_fresh)
    )
    mutations.extend(fresh_inventory_mutations)

    bad_fresh_trailing_key = copy.deepcopy(original)
    fresh_row = next(
        row
        for row in bad_fresh_trailing_key["fresh_adoption_vectors"]
        if row["id"] == "FABRIC-FRESH-COMMIT-OK-REOPEN-EXISTING"
    )
    meta_row = next(
        row
        for row in fresh_row["observed_rows"]
        if row["key_hex"] == b"FBM1".hex()
    )
    meta_row["key_hex"] += "00"
    mutations.append(("fresh-FBM-trailing-key", bad_fresh_trailing_key))

    bad_cu = copy.deepcopy(original)
    bad_cu["fba_commit_unknown_vectors"][0]["classification"] = "NEW"
    mutations.append(("CU-classification", bad_cu))

    for name, document in mutations:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.json"
            path.write_text(
                json.dumps(document, sort_keys=True), encoding="utf-8"
            )
            try:
                check_path(path)
            except GateError:
                continue
            raise GateError(f"self-test mutation survived: {name}")

    node_bad_crc = copy.deepcopy(original)
    value = bytearray.fromhex(node_bad_crc["storage_records"][0]["value_hex"])
    value[-1] ^= 1
    node_bad_crc["storage_records"][0]["value_hex"] = value.hex()
    node_mutations = [
        ("record-byte", node_bad_crc),
        *key_identity_mutations,
        *selection_inventory_mutations,
        *[
            (name, doc)
            for name, doc in mutations
            if name.startswith("selection-full-row-substitute-")
        ],
        ("selection-pre-retain-race-side-effect", bad_pre_retain_race),
        ("selection-post-retain-race-side-effect", bad_post_retain_race),
        ("durable-selection-divergence", bad_durable_selection),
        ("FBA-restart-side-effect", bad_fba_side_effect),
        ("FBA-exclusive-expiry", bad_fba_time),
        *fba_inventory_mutations,
        ("storage-enum-became-known", bad_storage_enum),
        ("NFL-enum-became-known", bad_nfl_enum),
        ("NFL-structural-boundary-expectation", bad_nfl_boundary_expected),
        ("fresh-reopen-outcome", bad_fresh_reopen),
        *fresh_inventory_mutations,
        ("fresh-FBM-trailing-key", bad_fresh_trailing_key),
    ]
    for name, document in node_mutations:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node-mutated.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            try:
                run_node(path)
            except GateError:
                continue
            raise GateError(f"Node self-test mutation survived: {name}")
    print("fabric bearer Python/Node gate self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            subprocess.run(
                [sys.executable, str(GENERATOR), "--check"], check=True
            )
            check_path(VECTOR)
            print("fabric bearer Python/Node specification gate: OK")
    except (GateError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"fabric bearer specification gate: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
