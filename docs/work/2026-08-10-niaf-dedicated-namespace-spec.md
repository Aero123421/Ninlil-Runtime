# NIAF dedicated namespace specification amendment

- Date: 2026-08-10
- State: SPEC_ACCEPTED specification amendment
- Scope: ADR-0039 restart checkpoint locator, key, and recovery boundary

## Decision

NIAF is not a Domain catalog row and does not share a canonical Domain schema-1
catalog namespace. It uses a caller-authoritative, exact dedicated namespace
under the existing Core/Foundation Domain Store durability authority. The
standalone Domain Store NIAF owner opens that namespace with storage schema 1,
holds the exclusive owner-context writer lease, and closes it.
There is no default, auto-prefix, LAB reuse, new wire, public API, or public
locator DTO.

The key is the exact 72-byte binary form defined in
`public-module-manifest.json#/identity_attachment_precondition_contract/restart_checkpoint_contract/storage_key`.
The order preserves the existing canonical identity:
realm, Runtime ID/generation, then module ID/generation. Recovery accepts only
an empty state or one exact current record. FULL update and `COMMIT_UNKNOWN`
classification use only the exact locator and key; OLD, NEW, and third values
are explicit and third values fence.

After `COMMIT_UNKNOWN`, the transaction is invalid: close, reopen the same
locator/schema, then use a fresh READ_ONLY zero-prefix full scan. First FULL
generation is 1; each accepted floor advance is checked `+1`; no-op writes
nothing; `UINT64_MAX`, rollback, wrap, or a lower floor fences. The KAT fixes
one independently reconstructed 72-byte key, offsets, and SHA-256.

## Boundary

The current public Composition API has no locator input. Adding one would be a
public ABI/DTO change, so this amendment deliberately requires a private
standalone NIAF owner before later private Composition injection. It does not
implement the owner, enable availability, change Domain schema1, or reuse a
LAB binding/store.

## Verification

- `tools/identity_attachment_precondition_spec_gate.py` checks the complete
  locator/key/recovery contract and rejects a locator mutation in self-test.
- `tools/public_module_manifest_gate.py` checks the exact manifest/schema
  contract and its immutable digest.

## Promotion boundary

The existing ADR-0039 review predates this amendment and remains historical.
The dedicated review at
`docs/reviews/2026-08-10-identity-attachment-precondition-niaf-s5-amendment-review.md`
records its independent GO and current contract digest. This remains a
specification-only acceptance, not an implementation task.
