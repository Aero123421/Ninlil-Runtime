# Ninlil V1 LAB — Developer guide

状態: V1 LAB RC 開発者向け（項目 10b）

## Repository レイアウト

| 領域 | パス |
| --- | --- |
| Public ABI | `include/ninlil/` |
| Private runtime | `src/runtime/`, `src/model/` |
| Transport / USB (C4) | `src/transport/c4_lab_*` |
| Radio (C5/C6) | `src/radio/c5_lab_*`, `c6_lab_*` |
| POSIX LAB platform | `ports/posix/lab_platform/` |
| Loopback bearer | `ports/posix/loopback_bearer/` |
| ESP-IDF port | `ports/esp-idf/` |
| Tests + gates | `tests/`, `tools/*_gate.py` |
| V1 examples | `examples/v1_lab/` |

## ビルドオプション

| Option | 既定（top-level） | 用途 |
| --- | --- | --- |
| `NINLIL_BUILD_TESTS` | ON | CTest・examples・private runtime |
| `NINLIL_ENABLE_SANITIZERS` | OFF（CI は ON） | ASan/UBSan |
| `NINLIL_BUILD_POSIX_SQLITE_STORAGE` | ON | POSIX SQLite port + LAB platform |

Host R7 crypto は top-level / tests ON 時に OpenSSL **3.x のみ** を要求します
（`CMakeLists.txt` 参照）。

## テスト実行（代表）

```bash
# 全 CTest（ローカルは tmp-v1 推奨）
ctest --test-dir tmp-v1 -j

# V1 統合 gate（RC 前必須）
ctest -R v1_integration_gate --test-dir tmp-v1 --output-on-failure

# V1 LAB examples
ctest -R 'v1_lab_.*_example' --test-dir tmp-v1 --output-on-failure

# 外部 consumer install smoke
tools/v1_lab_consumer_smoke.sh
```

## Provider / platform 拡張点

| 層 | 拡張方法 | V1 LAB 状態 |
| --- | --- | --- |
| `ninlil_platform_ops_t` | allocator/execution/clock/entropy/storage/bearer/tx_gate/origin | POSIX 全 slot 実装; ESP は matrix 参照 |
| Storage | `ninlil_posix_sqlite_storage` / ESP dual-slot | V1 durable success は **POSIX SQLite のみ** |
| Bearer | simulated / loopback / C4/C5 inject | host simulation |
| Enforcement | `c6_lab_enforcement` sole-edge | 項目 10a gate 必須 |

POSIX provider matrix: `docs/work/2026-07-23-v1-posix-provider-matrix.md`  
ESP provider matrix: `docs/work/2026-07-23-v1-esp-provider-matrix.md`

## 統合 topology（テスト専用）

`tests/support/v1_lab_integration_topology.{h,c}` は単一プロセスで
Controller + Endpoint + C4/C5 フルパスを結線します。examples の
Controller / Cell はこれを再利用します（install 対象外）。

Structural gate: `tools/v1_integration_gate.py` — bypass symbol が成功経路に
入らないことを検査。

## Packaging

| 成果物 | パス |
| --- | --- |
| LICENSE | `LICENSE` (Apache-2.0) |
| NOTICE | `NOTICE` |
| Third-party | `THIRD-PARTY-NOTICES.md` |
| 配布 manifest | `docs/v1-lab-distribution-manifest.md` |
| Consumer smoke | `tools/v1_lab_consumer_smoke.sh` → `cmake/installed_posix_sqlite_consumer_smoke.cmake` |

**V1 非主張:** SBOM、release signing、production license 最終監査（V2）。

## 項目別証拠（work）

| 項目 | 証拠 |
| --- | --- |
| 1–10a | `docs/work/2026-07-23-v1-a*.md`, integration gate |
| 10b | `docs/work/2026-07-23-v1-a10b-evidence.md` |
| RC 残件 | `docs/work/2026-07-23-v1-rc-residuals.md` |

## 禁止事項（V1 LAB RC）

- public ABI 変更（examples / docs 追加のみ可）
- 既存 test の弱化
- ESP durable FULL success の主張
- production / 国内実運用の主張
