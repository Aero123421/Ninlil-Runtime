# Ninlil V1 LAB 完成計画レビュー r2

対象: `docs/work/2026-07-23-ninlil-v1-lab-plan.md` rev2  
前回: `docs/work/2026-07-23-v1-plan-review-r1.md`（P0=6、P1=4、NO-GO）

## r1 P0 解消判定

### P0-1: 解消

項目1は V1-LAB durable profile を record kind・state・operation の closed allowlist とし、allowlist 外を生成しない writer/項目2〜9の構造 gate、publication 前の recovery reject、成功 evidence 0、unknown/corrupt/mixed/COMMIT_UNKNOWN の restart 負例を受入条件にした（対象計画 17 行）。D4 convergence も V1 allowlist 内 operation に限定して実装すると明記した（同 17 行）。

### P0-2: 解消

項目8は Hop/E2E、送受両方向、DATA/ACK lane、freshness/epoch fence、counter burn、replay state、clean restart、COMMIT_UNKNOWN restart を lifecycle の対象にした（対象計画 26 行）。M5 の代替として restart 時の fresh M4 handshake、旧 context の fence、nonce/key 非再利用、同 token/secret 再注入禁止、両 endpoint restart E2E を受入条件にした（同 26 行）。

### P0-3: 解消

10b に、public submit から source outcome まで USB、W1/L1、R9 host simulation、peer RX、durable evidence、authenticated ACK/Receipt を単一 topology で通す統合 E2E gate が追加された（対象計画 29–30 行）。障害注入、false success 0、bounded termination、範囲外 fail-closed、test-only direct loopback/bypass の structural check も受入条件に含まれる（同 30 行）。

### P0-4: 解消

項目4は bearer 別 exact single-frame/application 上限、上限内のみの admit、超過時の ownership/transaction/partial write/success evidence 0 と `REJECTED`、または実装済み別 bearer への決定的 route を要求する（対象計画 21–22 行）。`max-1/max/max+1`、restart、partial-apply=0 と、満たせない BoundedTransfer profile の public unsupported 化も受入条件に入った（同 22 行）。

### P0-5: 解消

項目1は成功可能な durable E2E を POSIX SQLite に限定した（対象計画 18 行）。HIL attestation のない ESP build では FULL/custody success、positive ACK/Receipt、payload release を構造的に発行不能とし、link/source gate と readback 一致時の負例を受入条件にした（同 18 行）。

### P0-6: 解消

§3 は完成受理を `1+2+3→7→8`、`1+2+3+4→5`、`1+2+3+4+7+8+10a→9`、`5+6+9→統合E2E→10b` の barrier に固定した（対象計画 45–54 行）。barrier 前は candidate、stub/fake provider/test credential 経路は未完成扱いとし、10a を項目9の送信可能化前に置いた（同 47、56–57 行）。

## r1 P1 反映確認

### P1-1: 一部未解消

family ごとの最小状態遷移・負例と、counter-offer の reserved/unsupported 化は追加された（対象計画 33 行）。一方、項目6には counter-offer を「生成/保存まで V1」とする記述が残り（同 24 行）、同 33 行の「V1 では生成もせず」と矛盾する。V1 の counter-offer 生成可否が一意でない。

### P1-2: 反映済み

全 provider catalog を対象に status、factory、owner、shutdown、restart、fault test、target link を持つ matrix と、LAB unavailable 時の明示 reject が受入 artifact に追加された（対象計画 34 行）。

### P1-3: 反映済み

10a に送信可能な全 frame type の exact-set manifest、R5 bind から R9 SPI までの sole-edge gate、各 permit 不成立時の SPI TX 0 が追加された（対象計画 28 行）。10a は packaging から分離され、項目9より前の barrier に置かれた（同 28、52、57 行）。

### P1-4: 反映済み

10b packaging に LICENSE/NOTICE/third-party notices、配布物 manifest、再現可能な外部 consumer build/install smoke が追加された（対象計画 31 行）。SBOM/signing は V2 とし、V1 RC の非主張として明記する条件がある（同 31 行）。

## 新規 P0 点検

新規 P0 なし。

P0=0 P1=1 判定=GO
