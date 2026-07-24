# Third-party notices (Ninlil V1 LAB)

This file lists third-party software that Ninlil **builds against** or
**redistributes notices for** in V1 LAB host packages. It is not an SBOM and
does not claim completeness for production compliance (V2).

## SQLite3

- **Use:** POSIX SQLite durable storage port (`ninlil_posix_sqlite_storage`).
- **Linkage:** system or toolchain-provided library at consumer build time.
- **License:** Public domain (see sqlite.org/copyright.html).

## OpenSSL 3.x

- **Use:** R7 Host private crypto adapter (AES-GCM, HKDF, SHA-256) when
  `NINLIL_BUILD_TESTS=ON` or top-level host builds that enable R7 Host crypto.
- **Linkage:** dynamic (`OpenSSL::Crypto`) on host CI/dev builds.
- **License:** Apache License 2.0 (OpenSSL 3.x). See OpenSSL project LICENSE.

## ESP-IDF / mbedTLS (target-only)

- **Use:** ESP-IDF component target builds (`ports/esp-idf`).
- **Linkage:** managed by ESP-IDF toolchain; not part of the installable host
  CMake package surface.
- **License:** per ESP-IDF component (mbedTLS: Apache 2.0).

## Not in V1 LAB RC scope

- SBOM generation, release signing, and production license audit are **V2**
  (see `docs/work/2026-07-23-ninlil-v1-lab-plan.md` §2).
