# Production Attachment PA-S2a crypto candidate review

Date: 2026-08-10  
Reviewer: Codex GPT-5.6 Sol xhigh, read-only  
Scope: private EDHOC symmetric/hash callback and platform crypto candidate  
Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Reviewed snapshot

- base HEAD: `fd01d234b4c38a020bb7137db57cba36d101ace0`
- 13-file reviewed implementation/spec input manifest SHA-256 (post-review
  README, work and review ledgers excluded):
  `ae4e5d13f5f9c0c5eae2feb175934304ca5c8f5650519611815e1ec3d36df3e5`
- ESP ELF SHA-256:
  `e8bf5c9c86722fcd1211af93cb71ca113d8ff1bb7d987cad361476fb048e350d`
- ESP BIN SHA-256:
  `e5bd56696c03bb9482fc757f9b012a10c58e8eda79460843f2478b194ddeed56`

## Accepted candidate evidence

- vendored libedhoc's exact `edhoc_keys` and `edhoc_crypto` callback shapes
  are used directly; no second public or general-purpose crypto ABI was added;
- the owner uses two fixed 64-byte key slots, an exact four-byte opaque key
  identifier, owner-lifetime generation checks, closed key types, and complete
  slot/owner zeroization;
- independent Host vectors cover SHA-256, RFC 5869 HKDF, RFC 3610 AES-CCM and
  RFC 8439 ChaCha20-Poly1305 rather than treating provider equality as an
  oracle;
- negative evidence covers suite-2 and suite-3 authentication failure,
  caller-output non-publication, wrong key type, malformed/stale/zero/wrapping
  key identifiers, capacity, reentry, live-key close, and owner/input/output
  aliasing;
- Host focused evidence passes **7/7** and ASan/UBSan passes **2/2** in the
  independent run;
- the explicit ESP-IDF v5.5.3 ESP32-S3 opt-in enables CCM, ChaCha20,
  Poly1305 and ChaChaPoly, compiles and links the same private source, exposes
  only three `GLOBAL HIDDEN` owner symbols, and records 22 stack rows with a
  maximum frame of **288 B**;
- the default build remains OFF, the candidate is uninstalled, and the public
  Runtime archive contains no PA-S2 symbol.

The Ponytail review found no redundant public layer, wire, store, owner or
Composition path. The platform implementation is a single private callback
adapter over OpenSSL 3 on Host and ESP-IDF-supplied mbedTLS on ESP32-S3.

## Status boundary

This GO accepts only the private PA-S2a symmetric/hash candidate. The ESP
artifact was compiled and linked but not flashed or executed. ESP target KAT,
Host/ESP byte equality, P-256 ephemeral/static ECDH, signature operations,
credential and membership authority, a complete EDHOC owner, PA-S2 as a whole,
PA-S3 through PA-S6, Composition, Join and physical HIL remain open. ADR-0023
and the full Identity/Attachment feature remain **Proposed**.
