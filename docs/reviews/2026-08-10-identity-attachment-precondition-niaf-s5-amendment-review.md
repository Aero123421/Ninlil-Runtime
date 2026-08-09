# Identity / Attachment precondition NIAF S5 amendment review

- Scope: ADR-0039 NIAF S5 namespace/key/recovery amendment
- Reviewed identity contract SHA-256: 2aacd200cd923265ef75ac512c2cf6732aeff0330f3e7a46fc88d7cb93ae4a8c
- S1: **CONFIRMED**
- S2: **CONFIRMED**
- S3: **CONFIRMED**
- S4: **CONFIRMED**
- S5: **CONFIRMED**
- S6: **CONFIRMED**
- Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Review summary

The amendment keeps the existing Core/Foundation Domain Store durability
authority while keeping NIAF outside the canonical Domain schema-1 catalog.
It fixes the caller-authoritative locator, exact 72-byte key, close/reopen
full-scan recovery after `COMMIT_UNKNOWN`, and fail-closed generation/floor
rules. The independent key KAT, manifest/schema identity, status coupling, and
mutation gates were reviewed.

## Non-claims

This is specification acceptance only. It does not implement the standalone
NIAF owner, Composition injection, Production Attachment, a public API/DTO,
wire format, Domain schema-1 catalog change, Join, Host/ESP execution, HIL, or
a release.
