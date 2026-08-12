# 2026-08-12 OSS review Fabric radio stack closure

## 対象

2026-08-11 OSS reviewで指摘されたESP32-S3のV1 radio RX call chainを対象にした。
修正前のHost Release `-fstack-usage`実測は次のとおりだった。

- `ninlil_fabric_private_tagged_sha256`: 4192 bytes
- `ninlil_v1_lab_radio_mapper_encode`: 3360 bytes
- `ninlil_v1_lab_radio_mapper_decode`: 2928 bytes
- `ninlil_fabric_private_nfl1_decode`: 2880 bytes
- `ninlil_fabric_private_nfl1_foundation_message_digest`: 2112 bytes
- `ninlil_v1_lab_radio_mapper_install_pair`: 2224 bytes

## 最小修正

- Fabric private SHA-256をincremental updateへ変更し、tag+value用4096-byte
  automatic bufferを削除した。既存one-shot APIとdigest bytesは維持した。
- NFL1 CRC helper自身がwire CRC fieldをzero扱いする契約へ合わせ、decode時の
  2048-byte packet copyを削除した。
- Foundation digestはzero正規化した2048-byte copyを作らず、同じcanonical byte列を
  7 spansとしてstreaming hashへ渡す。
- LAB radio mapperのbinding/NFL1/NRA1 scratchをowner objectへ移し、各call後に
  zeroizeする。公開API、wire、storage、feature stateは変更していない。
- 既存`.su` parserへexact source/artifact identity、`static` qualifier、malformed・
  duplicate拒否とself-testを追加し、Hostとofficial ESP launcherの両方で対象3 TUを
  2048-byte ceilingへ接続した。
- all-private Host profileでは同じFabric utility/codecがprivate Runtime archiveにも
  意図的に現れるため、Host gateはdirectory globではなく3つのauthoritative `.su`
  artifactをexact pathで選ぶ。別targetの同名objectを重複authorityとは数えない。
- official ESP launcher内のactive commandをexact 1件として構造gateへ固定した。
  command削除、commentだけのdecoy、source/root driftはいずれもREDになる。

## 検証

| 検証 | 結果 |
| --- | --- |
| NFL1 codec / Fabric lifecycle / radio mapping / stack gate | 5/5 PASS |
| ASan+UBSan focused tests | 5/5 PASS |
| Host Release source-only frames | max 848 bytes (ceiling 2048) |
| ESP-IDF v5.5.3 ESP32-S3 fresh V1 board build | PASS |
| ESP source-only frames | max 720 bytes (ceiling 2048) |
| launcher command deletion / decoy / source-root mutation | RED |
| malformed / dynamic / duplicate `.su` mutation | RED |
| ESP final ELF SHA-256 | `4660c2c7925460baa2dee40d95080856aca40ce53b8e09ee91b872d804010ade` |
| ESP final BIN SHA-256 / bytes | `78189f1ceb76c743f2f8229a1cb1ef8ce97c3dfb7e7d3a24abe902d111b194a9` / 516880 |
| `git diff --check` | PASS |

ESP buildはofficial ESP-IDF v5.5.3 linux/arm64 imageのlocal compile/link evidenceであり、
linux/amd64 release CI、flash、physical RF/USB HIL、Japan legal/field readinessは主張しない。
