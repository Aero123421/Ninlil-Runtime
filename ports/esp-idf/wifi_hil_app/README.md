# ESP32-S3 Wi-Fi physical HIL application

`wifi_hil_app` is the target composition for the private Wi-Fi V1 candidate:

```text
ESP32-S3 STA
  -> configured TCP client or listener
  -> exact TLS 1.3 mutual authentication
  -> peer-session exporter
  -> durable M4 FULL evidence
  -> attached-session exporter
  -> non-NULL Fabric packet-link and descriptor
```

The same firmware image contains both TLS roles. The retained NVS provision
selects `client` or `server` at boot. This is not SoftAP or discovery: the
client receives an exact numeric peer address; the server binds `LOCAL_ANY` on
an exact port.

Building this application is compile/link evidence only. Until two provisioned
boards are exercised through a real AP, serial status deliberately reports
`physical_ap_hil=NOT_RUN`.

## Secret handling

Wi-Fi credentials, CA/certificate/private key material, identity bindings, and
descriptor digests are accepted only from the `ninlil_wifi` NVS namespace.
There is intentionally no serial provisioning command. `STATUS` does not print
SSID, BSSID, IP address, runtime IDs, certificate data, keys, or digests.

Do not commit a manifest, generated CSV, staged files, or NVS image containing
real material. Use a private directory outside the repository.

## Create the NVS image

1. Copy `provisioning-manifest.example.json` to a private location.
2. Create SSID and PSK files without a trailing newline. The PSK must be
   8–63 bytes, or exactly 64 ASCII hexadecimal bytes.
3. Fill the manifest from the same certificate/controller provisioning
   authority used by the peer. `local_leaf_hex` and `peer_leaf_hex` are the
   exact 82-byte certificate binding values (164 hexadecimal digits). They
   must match the respective certificates; the TLS implementation verifies
   this again from the leaf certificates during the real handshake.
4. Export the repository-pinned ESP-IDF v5.5.3 environment and run:

```sh
python tools/wifi_hil_provision.py \
  --manifest /absolute/private/path/client.json \
  --output-dir /absolute/private/path/client-nvs
```

The tool validates field lengths, roles, authority/binding agreement, numeric
endpoint rules, PMF, password shape, and PEM bounds before invoking ESP-IDF's
NVS generator. It uses mode-`0600` files in a mode-`0700` temporary staging
directory and never prints secret contents. On normal success or failure it
best-effort overwrites, unlinks, and removes the staging files. Filesystems with
copy-on-write or wear levelling do not permit a secure-erasure claim; use an
encrypted private work volume when that distinction matters. The retained
result is:

```text
/absolute/private/path/client-nvs/wifi_hil_nvs.bin
```

For offline validation without an ESP-IDF environment, add `--csv-only`.
That mode intentionally retains the CSV and staging files because the CSV
references them; delete that private output directory after generating the
partition.

For a server manifest, set `"role": "server"` and omit
`endpoint.address`. Its local leaf must have role byte `0x02`; the peer leaf
must have role byte `0x01`. A client uses the opposite pair.

## Build and flash

```sh
idf.py -C ports/esp-idf/wifi_hil_app set-target esp32s3
idf.py -C ports/esp-idf/wifi_hil_app build
idf.py -C ports/esp-idf/wifi_hil_app flash monitor
```

Flash the generated NVS image by partition name, so the command follows the
application partition table rather than assuming an offset:

```sh
python "$IDF_PATH/components/partition_table/parttool.py" \
  --port /dev/tty.usbmodemXXXX \
  --partition-name nvs \
  write_partition \
  --input /absolute/private/path/client-nvs/wifi_hil_nvs.bin
```

Provision and flash a second board with the opposite role and swapped
local/peer leaf bindings. Both boards must share the AP profile, authority
group, assignment epoch, Fabric descriptor digest, registry epoch, and
attachment candidate digests required by the test configuration.

## Serial protocol

Commands are exact uppercase lines:

| Command | Meaning |
| --- | --- |
| `PING` | Liveness only |
| `STATUS` | Adapter state and whether the real Fabric surface is ready |
| `BUDGET` | Target owner/TLS/workspace size evidence |
| `FABRIC_OPEN` | Open the actual attached packet-link |
| `FABRIC_CLOSE` | Close the open packet-link |
| `REBOOT` | Reboot without erasing NVS |

`fabric_descriptor=ready packet_link=ready` is emitted only after the real
STA/TCP/TLS/exporter/M4/attached path has completed. It is not physical HIL
acceptance by itself; the physical runner must retain both board logs and the
AP/test topology as separate evidence.

## Evidence states

| Evidence | Honest status before hardware | What closes it |
| --- | --- | --- |
| ESP-IDF compile/link, final ELF and map | software evidence only | pinned v5.5.3 build and map/resource gates |
| NVS provisioning image | generated input, not connectivity proof | validated deterministic generation and recorded SHA-256 |
| STA/TCP/TLS/M4/Fabric runtime | `physical_ap_hil=NOT_RUN` | two provisioned ESP32-S3 boards complete the path through a real AP |
| Packet exchange | `physical_ap_hil=NOT_RUN` | retained sender/receiver logs and expected payload/result |
| disconnect/reconnect negatives | `physical_ap_hil=NOT_RUN` | controlled AP/peer interruption and fail-closed evidence |

Neither an ELF nor `fabric_descriptor=ready` is renamed to physical HIL PASS.

## Invalid manifest and NVS behavior

The offline tool exits with status `2` and does not generate an NVS image for
these classes. If equivalent corruption is introduced after generation, the
device reports `provision=2` (`CORRUPT`), does not create the adapter, and never
publishes a Fabric link.

| Invalid class | Examples |
| --- | --- |
| Schema/lifecycle | wrong schema, `enabled` not exact `true` |
| Wi-Fi policy | PMF false, unknown auth, channel outside `0..14` |
| Wi-Fi bytes | SSID outside 1–32 bytes, password outside 8–64 bytes, newline/NUL, non-hex 64-byte PSK |
| Role/identity | unknown role, local/peer role reversed, equal runtime IDs |
| Authority group | local/peer authority ID, term, or attachment binding differs |
| Endpoint | client missing/nonnumeric/zero/multicast address, link-local IPv6, server address present, port zero |
| Revision/IDs | zero revision/epoch, malformed/all-zero ID or digest |
| Certificate inputs | unreadable/wrong PEM type, embedded NUL, object outside 32–4095 bytes |
| Output safety | non-empty output directory; existing material is never overwritten |

## Exact NVS schema

Namespace: `ninlil_wifi`, schema: `1`.

| Key | NVS type | Constraint |
| --- | --- | --- |
| `schema` | `u32` | exact `1` |
| `enabled` | `u8` | exact `1` |
| `role` | `u8` | client `1`, server `2` |
| `auth` | `u8` | WPA2 `1`, WPA3 `2`, transition `3` |
| `pmf` | `u8` | exact `1` |
| `channel` | `u8` | `0..14` |
| `addr_kind` | `u8` | IPv4 `1`, IPv6 `2`, server LOCAL_ANY `3` |
| `peer_port` | `u16` | non-zero |
| `profile_rev`, `config_rev`, `assign_epoch` | `u64` | non-zero |
| `profile_id`, `cred_bind`, `instance_id`, `registry_epoch` | blob | exact 16 bytes, non-zero |
| `peer_addr` | blob | exact 16 bytes |
| `local_leaf`, `peer_leaf` | blob | exact 82 bytes |
| `fabric_desc`, `credential` | blob | exact 32 bytes, non-zero |
| `ssid` | blob | 1–32 bytes |
| `psk` | blob | 8–64 bytes |
| `ca_pem`, `cert_pem`, `key_pem` | blob | 32–4095 bytes each |

The application never auto-erases an unreadable or incompatible NVS
partition. Re-provision it explicitly so factory credentials are not silently
destroyed.
