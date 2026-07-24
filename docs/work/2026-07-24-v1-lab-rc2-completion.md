# V1 LAB RC2 completion record

日付: 2026-07-24  
対象: `v1.0-lab-rc2`

## 結論

V1 LAB RC2 は、隔離 LAB 向け host simulation の機能完成候補である。公開タグは、
本記録の検証、GitHub Actions、`main` 統合がすべて成功した後にだけ作成する。

## RC1 からの変更

- OSS 利用者が最初に判断できるよう README を再構成した。
- quickstart、developer guide、distribution manifest、security policy の状態表示を統一した。
- Leak example の SQLite Storage 初期化順を修正し、初回・再実行の両方を成立させた。
- docs-freeze gate を現行の文書構成へ追従させた。
- V1 LAB examples の POSIX feature-test macro を明示し、Linux strict C11 build を成立させた。
- SQLite optional build と SQLite-backed LAB E2E の依存境界を修正した。
- direct 1-hop test の cleanup path を GCC 13 strict build で安全に検査できるよう修正した。
- service exact-reattach test の未初期化 callback を修正し、構成依存の偶発成功を除去した。
- `main` に先行統合されていた Accepted 仕様・レビュー記録を取り込んだ。

## Local release gate evidence

| Gate | 結果 |
| --- | --- |
| fresh macOS sanitizer build | PASS |
| 全 CTest | PASS — 254 / 254 |
| V1 integration E2E gate | PASS |
| Controller / Cell / Display / Leak examples | PASS — 4 / 4 |
| installed consumer smoke | PASS — 4 configuration cases |
| SQLite3-disabled portable build | PASS |
| Linux GCC 13 strict example/direct-1hop compile | PASS |
| `git diff --check` | PASS |

GitHub Actions required checks、`main` 統合、annotated tag、GitHub prerelease は
GitHub 側の release procedure として順番に実施する。いずれかが失敗した場合は
タグを作成せず、RC2 を公開済みとして扱わない。

## Claim boundary

RC2 が主張するのは host simulation の機能完成だけである。ESP32-S3 の flash、
USB CDC、SX1262 physical RF、power-cut、Display / Leak 実機 E2E は未検証であり、
国内実運用可能、production 法規認定、field SLO は主張しない。
