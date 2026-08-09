# Third-party notices

This file lists direct and locked transitive software used by Ninlil's
supported build surfaces, plus vendored tooling dependencies shipped in the
current source tree. Host SDK archives do not bundle the linked libraries.
ESP-IDF firmware builds resolve their target components from the committed
component manifests and lock files.

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
- **Use:** Internal R7 crypto adapter (AES-GCM, HKDF, SHA-256) linked by the
  Host Runtime and host verification targets.
- **Linkage:** system-provided `OpenSSL::Crypto` on ordinary host development
  builds.  The Wi-Fi authority CI profile downloads the official OpenSSL
  3.5.7 source archive, verifies its pinned SHA-256 and peeled release commit,
  builds static `libssl` / `libcrypto` archives, and proves that the final
  verification binary has no dynamic OpenSSL dependency.  Those OpenSSL
  sources and archives are build inputs and are not bundled in Ninlil source
  or SDK archives.
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

## PyYAML 6.0.2 (vendored tooling dependency)

- **Machine ID:** `pyyaml`
- **Version:** `6.0.2`
- **Source path:** `tools/_vendor` (pure-Python wheel contents + dist-info/LICENSE)
- **Download:** `https://pypi.org/project/PyYAML/6.0.2/`
- **Component hash:** `00e9d5acfbcd65db22fb7ebc0637cd5920cf7ef43d512d059168026f72cc693a`
  (SHA-256 over relative paths under `tools/_vendor`, excluding `__pycache__`)
- **Use:** Release/workflow YAML semantic parsing for identity and packaging
  gates (`tools/yaml_semantic.py`). Bundled in the source archive so gates do
  not depend on a system PyYAML install.
- **License:** `MIT`
  ([PyYAML LICENSE](https://github.com/yaml/pyyaml/blob/master/LICENSE);
  also at `tools/_vendor/pyyaml-6.0.2.dist-info/licenses/LICENSE`).

## libedhoc 1.15.1 (private PA-S1a candidate)

- **Machine ID:** `libedhoc`
- **Version:** `1.15.1`
- **Component hash:** `75e49a0f740fd619b89727ef10325cfb7be71b43f256dfedd1e2fed5e4b6e980`
- **Source path:** `third_party/production_attachment_edhoc/libedhoc`
- **Use:** exact eight core and generated CBOR translation units for the
  default-OFF, uninstalled Production Attachment PA-S1a dependency candidate.
- **License:** `MIT` ([upstream LICENSE](third_party/production_attachment_edhoc/libedhoc/LICENSE)).

## zcbor d3093b5684f62268c7f27f8a5079f166772619de (private PA-S1a transitive candidate)

- **Machine ID:** `zcbor`
- **Version:** `d3093b5684f62268c7f27f8a5079f166772619de`
- **Component hash:** `c57f5db29b9dcfcf8b3dae0503496d83066a920160e65c6118aa059655b4efce`
- **Source path:** `third_party/production_attachment_edhoc/zcbor`
- **Use:** exact three CBOR runtime translation units required by the private,
  default-OFF PA-S1a candidate.
- **License:** `Apache-2.0` ([upstream LICENSE](third_party/production_attachment_edhoc/zcbor/LICENSE)).

## Scope boundary

This notice inventory does not replace a legal review. The release gate checks
the machine inventory (including vendored tooling), both committed lock files,
component manifest, notice tokens, Syft↔inventory reconciliation, enriched SBOM
package/version/license fields, and source archive before publication.
`HOST_CANDIDATE` / release-support completion is not claimed by notice updates.
