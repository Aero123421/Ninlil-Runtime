# 2026-07-28 Wi-Fi credential profile independent review

状態: **Proposed仕様候補の独立review GO — P0=0 / P1=0 / P2=0**

本記録は非規範である。Normative候補は
[ADR-0018](../adr/0018-wifi-bearer.md)と
[34章](../34-v2-runtime-fabric-completion.md)である。
このGOは`SPEC_ACCEPTED`、実装、target成立、HIL、`RELEASE_SUPPORTED`を意味しない。

## 対象

- `NINLIL-WIFI-CREDENTIAL-STORE-V1`
- NWS1 / NWA1 / NWC1 / NWP1 / NWM1
- NCM1 activation、2 bank FULL publish、restart
- local TLS role authority、root binding、key-binding history
- conservative reservation ceilingとconstraint-aware semantic maximum

## Review経過

初回の独立Sol high reviewはP0=0 / P1=2 / P2=1でNO-GOだった。

1. active 0 bankがNWA1 rootを拘束しない。
2. 64件のkey-binding history枯渇後のrolloverが安全に固定されていない。
3. provider reservation ceilingとsemantic maximumの説明が混在している。

修正後の再reviewで上記3件は閉じたが、configured local TLS roleのdurable正本がない
P1=1を検出した。NCM1 offset 60へ`local_role_mask`を割り当て、maskをNCM1 digest、
manifest generation、selector FULL publish、restart判定、旧session fenceへ含めた。
最終再reviewはP0=0 / P1=0 / P2=0でGOとなった。

## 独立再計算

Python `hashlib`/`struct`とNode `crypto`/Bufferの独立実装で、更新後NCM1 KATを
bit-exact照合した。

| active / retired / mask | total | manifest digest | complete SHA-256 |
| --- | ---: | --- | --- |
| 0 / 0 / 0 | 128 | `876ad2c5c0af8f78e1b8ad94ff78faee25612cd1d7c2e5b527092f1af69cbabb` | `5a211f3150216e65d0dcc8a6a69282db8f2411542e8f07a699736d8ffbf2ed69` |
| 1 / 0 / 1 | 184 | `9f5826074fb3ab217fd5df84f9628bb500cc24e248297cae4159cc8e6ac68382` | `56d5aaec32c7bb0be4a3e9521f77503606134f13a01ccb2955854ad90cacbc7b` |
| 1 / 1 / 1 | 280 | `5cb500100f1579a4f370dc4d5248d455a2ac08d313b419dd30598e2b4f4fec98` | `aae2cfcf2ba3b03cfb744e8c62eaa6997154dbdd452c921b25f856f40111a1fc` |
| 64 / 0 / 1 | 3712 | `b7fe4fc3f924e3aff1dc2ffc37f925ce28a9bf8dbc7de4627bc6a9b9922c7dd3` | `e2a7184830e888addb5e3c4da52f7ec3e6c958bcddcf0c1d13c3d3bd8805880a` |
| 0 / 64 / 0 | 6272 | `6e686fa61f91b50798ded3f9e567f8e56e858ad9c96f416d83120db004213267` | `644568e94b4702902f32f9f20b7d7ef0fa6984bf939b332e603f5da1b9bc3304` |

容量算術も次で一致した。

- conservative committed reservation: 606003 logical bytes / 25 keys
- conservative begin/final union: 1212006 logical bytes / 50 keys
- constraint-aware committed maximum: 600883 logical bytes
- constraint-aware begin/final union: 1201766 logical bytes

## 最終判定

- P0: 0
- P1: 0
- P2: 0
- Verdict: **GO（Proposed specification review only）**

`SPEC_ACCEPTED`にはADR-0018全体のS1〜S6、machine-readable KAT、関連文書同期、
独立security reviewが別途必要である。実装とHILはその後のgateで判定する。
