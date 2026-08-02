#!/usr/bin/env python3
"""PA-S0 fixture seeds (constants only — no formulas, no digests).

Shared factual inputs for emission and independent verification.
Does not import generator, r6_oracle, or verify_oracle.
"""

from __future__ import annotations

import hashlib


def _pattern(start: int, length: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(length))


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# Stable IDs are digests of fixed labels (NAI1 wire carries digests).
INITIATOR_STABLE_DIGEST = _sha256(b"initiator-stable-id")
RESPONDER_STABLE_DIGEST = _sha256(b"responder-stable-id")
SITE_DOMAIN = _pattern(0x20, 16)
AUTHORITY_ID = _pattern(0x30, 16)
ATTACHMENT_ID = _pattern(0x10, 16)
E2E_SECURITY_ID = _pattern(0x50, 16)
LEASE_CLOCK_EPOCH = _pattern(0x40, 16)

MEMBERSHIP_EPOCH = 11
ATTACHMENT_EPOCH = 13
AUTHORITY_TERM = 7
LEASE_EPOCH = 17
E2E_SECURITY_EPOCH = 73
CREDENTIAL_SET_REVISION = 19
REVOCATION_GENERATION = 31
ASSIGNMENT_EPOCH = 37

HOP_CONTEXT_IR = 41
HOP_CONTEXT_RI = 43
E2E_CONTEXT_IR = 47
E2E_CONTEXT_RI = 53
HOP_KEY_GENERATION_IR = 59
HOP_KEY_GENERATION_RI = 61
E2E_KEY_GENERATION_IR = 67
E2E_KEY_GENERATION_RI = 71

# Expected AL floors after install (context_id + 1).
AL_FLOOR_BY_CONTEXT = {
    HOP_CONTEXT_IR: 42,
    HOP_CONTEXT_RI: 44,
    E2E_CONTEXT_IR: 48,
    E2E_CONTEXT_RI: 54,
}

INSTALL_LABEL = b"NINLIL-PRODUCTION-ATTACH-INSTALL-V1"
CARRIER_TRANSCRIPT_LABEL = b"NINLIL-PA-CARRIER-TRANSCRIPT-V1"
assert len(CARRIER_TRANSCRIPT_LABEL) == 31


def install_fields_dict() -> dict:
    return {
        "attachment_id": ATTACHMENT_ID,
        "initiator_stable_digest": INITIATOR_STABLE_DIGEST,
        "responder_stable_digest": RESPONDER_STABLE_DIGEST,
        "site_domain": SITE_DOMAIN,
        "authority_id": AUTHORITY_ID,
        "authority_term": AUTHORITY_TERM,
        "membership_epoch": MEMBERSHIP_EPOCH,
        "attachment_epoch": ATTACHMENT_EPOCH,
        "lease_epoch": LEASE_EPOCH,
        "e2e_security_id": E2E_SECURITY_ID,
        "e2e_security_epoch": E2E_SECURITY_EPOCH,
        "credential_set_revision": CREDENTIAL_SET_REVISION,
        "revocation_generation": REVOCATION_GENERATION,
        "assignment_epoch": ASSIGNMENT_EPOCH,
        "hop_context_ir": HOP_CONTEXT_IR,
        "hop_context_ri": HOP_CONTEXT_RI,
        "e2e_context_ir": E2E_CONTEXT_IR,
        "e2e_context_ri": E2E_CONTEXT_RI,
        "hop_key_generation_ir": HOP_KEY_GENERATION_IR,
        "hop_key_generation_ri": HOP_KEY_GENERATION_RI,
        "e2e_key_generation_ir": E2E_KEY_GENERATION_IR,
        "e2e_key_generation_ri": E2E_KEY_GENERATION_RI,
    }
