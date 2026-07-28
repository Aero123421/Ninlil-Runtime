# Third-party notices

This file lists direct and locked transitive software that Ninlil builds
against in the current source tree. Host SDK archives do not bundle these
libraries. ESP-IDF firmware builds resolve their target components from the
committed component manifests and lock files.

Every new tag published through the current release workflow includes a
generated SPDX JSON SBOM enriched from `dependency-inventory.json`. Historical
LAB tags may not. The inventory is the source-release dependency authority;
the applicable dependency source distribution remains authoritative for its
per-file notices.

## SQLite3

- **Machine ID:** `sqlite3`
- **Version:** `system-provided`
- **Use:** POSIX SQLite durable storage port (`ninlil_posix_sqlite_storage`).
- **Linkage:** system or toolchain-provided library at consumer build time.
- **License:** `blessing` (public-domain dedication)
  ([SQLite copyright statement](https://sqlite.org/copyright.html)).

## OpenSSL 3.x

- **Machine ID:** `openssl`
- **Version:** `3.x` (`>=3.0.0 <4.0.0`)
- **Use:** R7 Host private crypto adapter (AES-GCM, HKDF, SHA-256) when
  the Host Runtime or host verification targets are enabled.
- **Linkage:** dynamic (`OpenSSL::Crypto`) on host CI/dev builds.
- **License:** `Apache-2.0` (OpenSSL 3.x). See the
  [OpenSSL license](https://github.com/openssl/openssl/blob/master/LICENSE.txt).

## ESP-IDF 5.5.3 / mbedTLS (target-only)

- **Machine ID:** `idf`
- **Version:** `5.5.3`
- **License:** `Apache-2.0`
- **Use:** ESP-IDF component target builds (`ports/esp-idf`).
- **Linkage:** managed by ESP-IDF toolchain; not part of the installable host
  CMake package surface.

Mbed TLS is a bundled ESP-IDF dependency:

- **Machine ID:** `mbedtls`
- **Version:** `ESP-IDF-5.5.3`
- **License:** `Apache-2.0 OR GPL-2.0-or-later`
- **Use:** ESP-IDF target crypto provider. Ninlil selects the Apache-2.0 option
  where applicable.

## esp_tinyusb 2.1.1 (target-only)

- **Machine ID:** `espressif/esp_tinyusb`
- **Version:** `2.1.1`
- **Component hash:** `fa0c96d7bdc3fe37383d735e2839a9007200a0b6bc039458d45d004b50146e81`
- **Use:** ESP32-S3 USB CDC target adapter.
- **Resolution:** exact direct dependency in
  `ports/esp-idf/components/ninlil/idf_component.yml`; exact lock in both ESP
  applications.
- **License:** `Apache-2.0`
  ([Espressif Component Registry](https://components.espressif.com/components/espressif/esp_tinyusb/versions/2.1.1/versions)).

## espressif/tinyusb 0.21.0~1 (target-only transitive dependency)

- **Machine ID:** `espressif/tinyusb`
- **Version:** `0.21.0~1`
- **Component hash:** `a72b7d67472914ab76309340fd50d578b31e310963d45ad0f81144bde3314752`
- **Use:** USB device stack selected by `esp_tinyusb`.
- **Resolution:** exact transitive version and component hash in the committed
  ESP application lock files.
- **License:** `MIT`
  ([Espressif Component Registry](https://components.espressif.com/components/espressif/tinyusb/versions/0.21.0~1/readme)).

## Scope boundary

This notice inventory does not replace a legal review. The release gate checks
the machine inventory, both committed lock files, component manifest, notice
tokens, enriched SBOM package/version/license fields, and source archive before
publication.
