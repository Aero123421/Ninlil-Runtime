# R7 Wi-Fi `OTHER_REGISTERED` target-software candidate close

- Date: 2026-07-29
- Scope: ADR-0018 §§14.1.1/14.5 missing R7 co-tenant allocation owner
- Decision artifact: ADR-0026
- Decision status: **Proposed implementation candidate — independent review pending**
- Physical allocator trace: **NOT_RUN**
- Physical AP HIL: **NOT_RUN**
- ADR-0018 C7/C8: **RED**

## Outcome

The ESP mbedTLS R7 raw adapter is no longer unowned or implicitly charged to
`CRYPTO_GLOBAL` in the private Wi-Fi composition.  It has one closed
`OTHER_REGISTERED(R7_RAW_V1)` owner, a 304-byte INTERNAL reservation, bounded
diagnostics, explicit release, and fail-closed owner/fault handling.

The first draft inferred a 280-byte maximum from HKDF alone.  A real
ESP32-S3 target compile disproved that inference: the effective ESP-IDF v5.5.3
configuration does not define `MBEDTLS_BLOCK_CIPHER_C`.  The active GCM path is
therefore:

```text
mbedtls_gcm_setkey
  -> mbedtls_cipher_setup
  -> cipher_wrap AES ctx_alloc
  -> mbedtls_calloc(1, sizeof(mbedtls_aes_context))
```

The target request is 280 bytes.  With the pinned arena header, tail, and
alignment, its charged span is 304 bytes.  HKDF's simultaneous SHA/HMAC charge
is `128 + 152 = 280` bytes, so GCM is the actual reservation maximum.

## Closed contract

| Item | Exact value |
| --- | ---: |
| component id | `0x52375231` (`R7R1`, non-wire) |
| R7 `OTHER_REGISTERED` reservation | 304 bytes INTERNAL |
| Wi-Fi + R7 total reservation | 262448 bytes |
| tiered internal envelope | 164144 bytes |
| conservative internal-only feasibility | 327984 bytes |
| allocator trace capacity | 32 records |

The allocator admits no unknown or duplicate `OTHER_REGISTERED` family.
Every R7 SHA-256, HKDF Extract/Expand, and AES-128-GCM Seal/Open callback enters
and leaves the R7 owner.  Ordinary arena OOM remains local and retryable.
Missing bootstrap, unowned/cross-owner allocation or free, foreign/double free,
recursive/concurrent callback use, wrong leave, damaged arena metadata, or
release with outstanding allocations establishes the process-wide fatal fence.

## Host evidence

The Host test compiles the exact production allocator, resource policy,
portable R7 wrapper, and ESP mbedTLS adapter against a deterministic fake
ESP/mbedTLS boundary.

```sh
cmake --build build-r7-cotenant \
  --target wifi_v1_r7_other_registered_fault_test -j4
ctest --test-dir build-r7-cotenant --output-on-failure \
  -R '^wifi_v1_r7_other_registered_fault_test$'
```

Result: `1/1 PASS`.

```sh
cmake --build build-r7-cotenant-san \
  --target wifi_v1_r7_other_registered_fault_test -j4
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 \
ctest --test-dir build-r7-cotenant-san --output-on-failure \
  -R '^wifi_v1_r7_other_registered_fault_test$'
```

Result: `1/1 PASS` under AddressSanitizer and UndefinedBehaviorSanitizer.
Apple's ASan leak detector is unsupported, so `detect_leaks=0` is explicit and
this result does not claim separate leak-sanitizer evidence.

The ESP adapter also compiles with `ESP_PLATFORM` and `MBEDTLS_HKDF_C` but
without `NINLIL_ENABLE_PRIVATE_WIFI_V1`, proving that the standalone R7
provider keeps its prior `ctx == NULL` boundary and does not acquire a Wi-Fi
composition dependency.

Covered cases include bootstrap-before-crypto, HKDF and GCM allocation/free,
two TLS sessions plus R7 aggregate arithmetic, local OOM and retry, cross-owner
and foreign/double free, recursive provider entry, allocator recursion,
wrong/double enter/leave, outstanding-allocation close, trace overflow,
unknown/duplicate registration, and duplicate provider factory output
non-mutation.

## Pinned ESP-IDF v5.5.3 evidence

Reproducible clean command:

```sh
bash tools/wifi_v1_esp_idf_map_proof_local_arm64.sh
```

Result: `PASS` using:

- image:
  `docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1`
- container architecture: `aarch64`
- ESP-IDF: `v5.5.3`
- target: `esp32s3`
- final owner workspace: 9008 bytes, ceiling 12288
- final DIRAM: used 171703, total 341760, free 170057
- candidate envelope: 164144, link slack 5913
- stack-usage frames checked: 384, ceiling 8192

Final-ELF target probes:

| Probe | Measured bytes |
| --- | ---: |
| `sizeof(max_align_t)` | 16 |
| `_Alignof(max_align_t)` | 8 |
| SHA-256 context request | 108 |
| SHA-256 arena charge | 128 |
| HMAC arena charge | 152 |
| AES context request | 280 |
| GCM arena charge | 304 |
| R7 reservation | 304 |

The closure gate pins the active `hkdf.c`, `md.c`, `gcm.c`, `cipher.c`,
`cipher_wrap.c`, `gcm.h`, and `aes.h` hashes; repository source hashes; R7
GCM/HKDF final roots; archive definitions and undefined relocations; exact
target probes; and final map retention.

Canonical closure root:

```text
755959d4d2d7f00501b1967e1aa7002fb39a5460cbb54e137fd47323176c0387
```

The HIL image runs RFC 5869 and AES-128-GCM known-answer checks before Wi-Fi
provision loading, requires zero current/outstanding R7 allocations and the
exact 304-byte peak, and exposes the bounded metadata-only
`R7_ALLOC_TRACE` serial command.  The trace never prints pointers, keys,
payloads, credentials, or peer identifiers.

## Non-claims and remaining promotion boundary

This closes a **target-software candidate**, not physical acceptance:

- no ESP32-S3 image was flashed or executed in this tranche;
- no physical allocator peak/trace transcript was captured;
- no physical AP, dual-board, RF, or legal-compliance test was run;
- the local arm64 proof does not replace the separate release/CI amd64 lane;
- ADR-0026 remains Proposed until independent review; and
- ADR-0018 C7/C8 and `RELEASE_SUPPORTED` remain red.

Future physical evidence must flash the exact closure-root image, capture
`STATUS` and `R7_ALLOC_TRACE`, prove `r7_peak=304`,
`r7_outstanding=0`, `allocator_fatal=0`, no dropped required trace segment,
and then run the broader Wi-Fi/AP HIL acceptance separately.

## Subsequent acceptance

On 2026-07-30 the exact source, Host fault behavior, target probes, final
ELF/map, and closure evidence passed
[independent review](../reviews/2026-07-30-r7-wifi-other-registered-final-review.md)
with P0/P1/P2 all zero. ADR-0026 is now Accepted for this narrow
target-software composition decision. The physical non-claims above remain
unchanged: ADR-0018 and both Wi-Fi compatibility entries are still
`PROPOSED`, C7/C8 are RED, and physical allocator/AP HIL is `NOT_RUN`.
