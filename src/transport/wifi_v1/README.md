# Private Wi-Fi v1 (ADR-0018)

Default-OFF private candidate. Not installed. Not public ABI.

## Host (OpenSSL 3)

```bash
cmake -S . -B build \
  -DNINLIL_ENABLE_PRIVATE_WIFI_V1=ON \
  -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON \
  -DNINLIL_BUILD_TESTS=ON
cmake --build build --target wifi_v1_host_e2e_driver
ctest --test-dir build -R 'wifi_v1_' --output-on-failure
```

## Modules

| File | Role |
| --- | --- |
| `wifi_nwb1.*` | NWB1 framing + CRC32C + structural NFL1 check |
| `wifi_stream.*` / `wifi_queues.*` | RX stream reassembly, TX/RX backpressure queues |
| `wifi_tcp_posix.*` / `wifi_tls_host.*` | Host nonblocking TCP + TLS1.3 mTLS |
| `wifi_tls_export.*` | Context builders 62/64 → exporter IDs 16/16 (not inverted) |
| `wifi_journal.*` | Durable attempt journal (storage CU) |
| `wifi_reconnect.*` | Exponential backoff + endpoint rotation |
| `wifi_credentials.*` | stage / activate / revoke (`secret_ref_digest` only) |
| `wifi_session.*` | Host session; M4 PA FULL required before ATTACHED/NWB1 |
| `wifi_fabric_adapter.*` / `wifi_fabric_link_ops.c` | Per-send distinct tokens + Fabric contract |
| `wifi_esp_sta.*` | ESP STA, `WIFI_STORAGE_RAM` |
| `wifi_esp_tcp.*` | ESP lwIP sockets |
| `wifi_esp_tls_mbedtls.*` | ESP direct mbedTLS TLS1.3 exporters (16-byte IDs) |
| `wifi_esp_owner.*` | Async sole-owner events; GOT_IP before TCP/TLS |

### Phase rule (non-negotiable)

```text
HANDSHAKING → CHANNEL_AUTHENTICATED → PEER_SESSION
  → (M4 PA FULL confirm) → ATTACHED → NWB1 only
```

TLS alone never enables NWB1. Caller-provided session_id is never identity.

### Exporter contract

```text
peer_context[62]  → TLS-Exporter(PeerSession-v1, ctx, 16) → peer_session_id[16]
attached_context[64] → TLS-Exporter(NWB1-Attached-v1, ctx, 16) → session_id[16]
```

Contexts are inputs; IDs are outputs. Never invert.

### Fabric poll contract

`poll_send` with in-flight work returns **`FABRIC_LINK_OK` + `COMPLETION_PENDING`**.
Returning `WOULD_BLOCK` for PENDING causes Fabric core to fence the attempt.

### ESP 12 KiB

`sizeof(ninlil_wifi_esp_owner_t) == 10728` (measured) ≤ 12288. TLS object is external.

## ESP

Kconfig: `CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1` (default n).

```bash
# Official container map proof (native amd64 CI preferred):
bash tools/wifi_v1_esp_idf_map_proof.sh
```

`ports/esp-idf/wifi_hil_app` serial surface: `PING`, `STATUS`, `OWNER_INIT`,
`OWNER_FENCE`, `STA_INIT`, `BUDGET`. Does not log secrets. Does not claim AP/HIL.
