# 2026-07-29 Private Wi-Fi v1 — arm64 local map proof + P0/P1 close

状態: **private / default-OFF** — not Host candidate GO, not `SPEC_ACCEPTED`,
not `RELEASE_SUPPORTED`. Physical AP/HIL **NOT_RUN**.

## Image authority split

| Use | Platform | Digest |
| --- | --- | --- |
| **Local Apple Silicon** | `linux/arm64` (native, no QEMU) | `sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1` |
| **CI/release** (`tools/esp_idf_ci_docker_run.sh`) | `linux/amd64` | `sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb` |

Helpers:

- `tools/wifi_v1_esp_idf_map_proof_local_arm64.sh` — local arm64 only
- `tools/wifi_v1_esp_idf_map_proof.sh` — auto: arm64 host → local helper; else CI amd64

## Host evidence (ASan/UBSan)

```text
wifi_v1_* 9/9 PASS (ctest -R wifi_v1_)
  nwb1, credentials, journal, reconnect, exporter_kat,
  attachment_gate, esp_owner (measured=10728), fabric_link, host_e2e
```

## ESP final-ELF / map (arm64 native) — blockers closed

### Blocker fixes
1. **SHA provider split**: `wifi_sha256.h` + `wifi_sha256_host.c` (OpenSSL Host) +
   `wifi_sha256_mbedtls.c` (ESP). `wifi_reconnect.c` / `wifi_journal.c` include **only**
   `wifi_sha256.h` — **zero** `openssl/sha.h` on ESP path.
2. **esp_event/esp_wifi REQUIRES**: `PRIV_REQUIRES` lists `esp_event esp_wifi esp_netif
   nvs_flash lwip` when Wi-Fi ON; plus `target_link_libraries(idf::esp_event …)`.
   `compile_commands.json` for `wifi_esp_sta.c` includes esp_event + esp_wifi paths.

```text
container_arch=aarch64
idf_version=ESP-IDF v5.5.3
image_digest=sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
platform=linux/arm64
sha256_provider=wifi_sha256_mbedtls.c

ELF: ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.elf
MAP: ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.map
BIN: ninlil_wifi_hil.bin size 0x39740

resource_gate:
  OK symbols: owner_init/step, nwb1_encode (+ sha256 in map)
  OK measured owner workspace 10728 <= 12288

nm shows: ninlil_wifi_sha256 from wifi_sha256_mbedtls.c.obj
          ninlil_wifi_esp_sta_init, ninlil_wifi_reconnect_init
evidence: ports/esp-idf/wifi_hil_app/build/wifi_hil_evidence.txt
physical_ap_hil=NOT_RUN
claim=final_elf_map_composition_only
```

Reproduce:

```bash
bash tools/wifi_v1_esp_idf_map_proof_local_arm64.sh
# or auto on arm64 host:
bash tools/wifi_v1_esp_idf_map_proof.sh
```

## Non-claims

- No physical AP association / DHCP / on-air TLS HIL
- No Host candidate / SPEC_ACCEPTED
- No public ABI
- CI still uses amd64 digest only for release authority
