# ADR-0026: R7 raw crypto as a Wi-Fi allocator `OTHER_REGISTERED` co-tenant

- Status: **Accepted (target-software composition decision)**
- Date: 2026-07-30
- Relates: ADR-0011 (Accepted R7 private provider candidate), ADR-0018
- Supersedes: none

## Context

ADR-0018 §§14.1.1 and 14.5 require every direct mbedTLS caller in the Wi-Fi
composition to use the sole profile allocator under one of three owner classes:
`CRYPTO_GLOBAL`, `TLS_SESSION(channel_instance_id)`, or
`OTHER_REGISTERED(component_id)`.  The only admitted co-tenant is the Accepted
R7 ESP mbedTLS raw-adapter family.

The implementation before this ADR had only `CRYPTO_GLOBAL` and `TLS_SESSION`
owners.  `ports/esp-idf/src/r7_crypto_mbedtls.c` could call HKDF without an
owner scope.  Charging that work to `CRYPTO_GLOBAL`, or treating it as
allocation-free, would be false:

- pinned ESP-IDF v5.5.3 `hkdf.c` calls `mbedtls_md_hmac()` for Extract and
  `mbedtls_md_setup(..., 1)` for Expand;
- pinned `md.c` allocates one SHA-256 context and a `2 * 64` byte HMAC buffer
  with `mbedtls_calloc`;
- the effective target configuration does **not** define
  `MBEDTLS_BLOCK_CIPHER_C`; and
- pinned `gcm.c` therefore calls `mbedtls_cipher_setup()`, whose legacy
  `cipher.c`/`cipher_wrap.c` path allocates one `mbedtls_aes_context` with
  `mbedtls_calloc`.

The existing ADR-0018 values `262144` bytes total and `327680` bytes
internal-only feasibility contain no R7-specific reservation.  This ADR does
not silently redefine those values.

## Decision

### Owner and lifecycle

1. The closed component id `NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1`
   identifies the one admitted `OTHER_REGISTERED` family.  Unknown ids,
   duplicate registration, or a second registered family fail closed.
   The composed adapter publishes one provider handle at a time; a duplicate
   factory call fails without mutating its output, so closing one handle can
   never invalidate an aliased second handle.
2. In a build that composes private Wi-Fi v1 with the R7 ESP adapter, the R7
   provider factory performs allocator bootstrap before its first crypto call,
   then reserves and registers the R7 owner.  Standalone R7 builds retain their
   existing provider behavior and do not acquire the Wi-Fi composition
   dependency.
3. Every R7 SHA-256, HKDF-Extract, HKDF-Expand, GCM-Seal, and GCM-Open raw
   callback enters the R7 owner before the mbedTLS call and leaves it on every
   path.  Owner scopes are synchronous and non-recursive.  An atomic guard
   converts concurrent or recursive callback entry into the same fatal fence
   without introducing a C data race.
4. Missing bootstrap, cross-owner entry/free, recursive callback, double or
   foreign free, wrong/double leave, arena metadata damage, and unowned
   allocation set the process-wide fatal fence.  Ordinary R7 arena OOM is a
   local backend failure; it does not spill to another arena and does not get
   recharged to `CRYPTO_GLOBAL`.
5. Provider close is explicit.  It requires R7 current bytes and outstanding
   allocations to be exactly zero before zeroizing and releasing the
   reservation.  It does not release `CRYPTO_GLOBAL`, which may still be used
   by Wi-Fi sessions.

### Exact target-software candidate budget

The target ABI and allocator layout are part of the closure gate:

- `sizeof(max_align_t) == 16`, `_Alignof(max_align_t) == 8`;
- arena allocation header = 16 bytes, tail canary = 4 bytes, alignment = 8;
- SHA-256 context request is 108 bytes and has charged span 128 bytes;
- HMAC buffer request `2 * 64 == 128` has charged span 152 bytes; and
- AES context request is 280 bytes and has charged span 304 bytes.

Extract and Expand each have a maximum simultaneous charge of
`128 + 152 = 280` bytes.  GCM Seal and Open each reach the larger 304-byte
AES-context charge.  The five callbacks are serialized by the owner scope, so
the maximum of those callback peaks—not their sum—is the exact reservation.
Therefore the accepted target-software R7 reservation is:

| Candidate reservation | Exact bytes | Capability |
| --- | ---: | --- |
| `OTHER_REGISTERED(R7_RAW_V1)` | 304 | `MALLOC_CAP_INTERNAL \| MALLOC_CAP_8BIT` |
| Wi-Fi + R7 composition allocation reservation | 262448 | existing 262144 + 304 |
| tiered internal composition envelope | 164144 | existing 163840 + 304 |
| conservative internal-only feasibility | 327984 | existing 327680 + 304 |

These are **accepted target-software composition values** for the narrow
R7/Wi-Fi co-tenant decision.  They do not promote ADR-0018 or either Wi-Fi
compatibility-matrix entry.  Target compile/static-source closure can establish
a bound, but it is not a physical peak trace.

### Evidence and diagnostics

- A Host fault target compiles the exact ESP allocator/R7 wrapper sources
  against a deterministic fake ESP/mbedTLS boundary.  It covers
  bootstrap-before-crypto, exact owner entry/leave, normal allocation/free,
  OOM, cross-owner, double/foreign/recursive faults, fatal fencing, aggregate
  arithmetic, and close/outstanding behavior.
- The ESP-IDF v5.5.3 closure gate pins the exact R7 callback roots, allocator
  roots, source hashes, target ABI/type-size probes, archive members,
  relocations, final-map retention, and a canonical closure-root SHA-256.
- A fixed-capacity trace records bounded owner/callback/allocation events and
  overflow status without allocating.  It is HIL-ready; passing a Host test or
  compiling/linking an ESP image is not a target execution result.

## Acceptance boundary

The exact source and closure evidence passed independent review in
[`2026-07-30-r7-wifi-other-registered-final-review.md`](../reviews/2026-07-30-r7-wifi-other-registered-final-review.md)
with P0/P1/P2 all zero.  This acceptance is deliberately narrow:

- ESP target compile/archive/ELF/map/closure gate is software evidence only;
- allocator runtime peak, physical PSRAM/internal-heap behavior, and device
  callback trace remain `NOT_RUN` until captured on ESP32-S3 hardware; and
- ADR-0018 C7/C8 and `RELEASE_SUPPORTED` remain red until their broader
  Wi-Fi/LwIP and physical-HIL requirements are satisfied.
