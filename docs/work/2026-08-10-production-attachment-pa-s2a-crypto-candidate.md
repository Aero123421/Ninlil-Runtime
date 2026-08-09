# PA-S2a private EDHOC symmetric/hash candidate

Date: 2026-08-10  
Status: **independently reviewed Host KAT candidate / ESP32-S3 compile-link-stack only; PA-S2 remains open**

The spec boundary received a pre-implementation review GO. The frozen
implementation then received an independent final review result of
**GO — P0=0 / P1=0 / P2=0 / P3=0**. This candidate result does not promote
ADR-0023 or complete PA-S2.

## Scope

This tranche binds the vendored libedhoc `edhoc_keys` and `edhoc_crypto`
callback shapes to a private, default-OFF, uninstalled primitive backend. It
adds no public header/API/DTO, wire or storage record, credential provider,
EDHOC state owner, Composition/NIAF connection, task, pump, or LAB dependency.
It does not change or reuse the R7 crypto ABI.

The caller-owned owner is serialized and fixed at two 64-byte raw-key slots
plus a 528-byte workspace. A four-byte opaque key id contains a slot number and
a non-zero 24-bit slot generation that does not wrap within one begun owner
lifetime. Only `EXTRACT`, `EXPAND`,
`ENCRYPT`, and `DECRYPT` key types are accepted. Destroy wipes the complete
slot and owner close wipes the complete owner. Callback and binding spans that
overlap the owner, or conflicting input/output spans, are rejected before
publication. There is no raw-key getter.

## Evidence

- Host OpenSSL 3 KAT: SHA-256 `abc`, RFC 5869 HKDF case 1, RFC 3610
  AES-CCM packet vector 1, and RFC 8439 ChaCha20-Poly1305 section 2.8.2.
- Exact libedhoc context init, user-context set, key/crypto binding, and
  deinit use the adopted PA-S1a dependency. ECDH and signature callbacks are
  non-null fail-closed `NOT_SUPPORTED` stubs.
- Negative checks cover unsupported key types, wrong suite key size, two-slot
  exhaustion, stale and wrapping generations, immediate slot/owner
  zeroization, callback reentry, AEAD authentication failure with no output,
  owner alias, callback-output alias, and partial input/output overlap.
- Focused normal and ASan/UBSan Host suites pass PA-S1a and PA-S2a 2/2.
- ESP-IDF v5.5.3 explicit opt-in enables CCM, ChaCha20, Poly1305, and
  ChaChaPoly, compiles the same private source, and links all three private
  owner symbols as `GLOBAL HIDDEN`. Stack evidence has 22 PA-S2a rows; maximum
  frame is 288 bytes (`platform_seal` / `platform_open`) under the 2048-byte
  ceiling.
- Fresh ESP32-S3 compile/link artifact:
  `build-pa-s2-edhoc-optin-final/ninlil_m3_combined_smoke.elf`, SHA-256
  `e8bf5c9c86722fcd1211af93cb71ca113d8ff1bb7d987cad361476fb048e350d`.
  The corresponding 522,960-byte binary has SHA-256
  `e5bd56696c03bb9482fc757f9b012a10c58e8eda79460843f2478b194ddeed56`
  and leaves 67% of the smallest application partition free. It was not
  flashed or executed.

## Open evidence

ESP target execution of the same KAT bytes, Host/ESP cross-provider equality,
suite-3 target correctness, P-256 ephemeral/static ECDH, signatures, Factory
Identity and Site Membership authorities, credential resolution, a bounded
EDHOC/Attachment owner, messages 1 through 4, exporter use, PA-S3 through
PA-S6, and physical HIL remain open. OpenSSL and ESP
mbedTLS provider-internal allocation are outside this candidate's fixed-resource
accounting and do not establish a production ceiling. PA-O03, PA-O04, full
PA-S2, and ADR-0023 therefore remain `OPEN` / `Proposed`.
