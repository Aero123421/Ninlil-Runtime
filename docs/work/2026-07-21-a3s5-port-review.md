# A3-S5 移植確認 (2026-07-21) — NO-GO P1=3 P2=1

所見（NO-GO）
- P1: [§18.2 D3-S6行](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2357)に、[§18.16の明示移管](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:5971)で要求された「RETIRED node自身のoutgoing successor suffix walk / chain authority」が未反映。規範上の所有範囲が閉じていません。
- P1: [§18.4](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2399)と[§18.10](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2571)がS4までのouter `10880`を最新値として残しており、§18.16のS5 `651/656`・full outer `11536`と矛盾します。
- P1: architecture mirrorが未更新です。[§18.3](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2367)にS5a same-txn specializationなし、[§18.5 category E](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2410)と[`k`表](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2424)に§18.16・`k₅=1`なし、[§18.6 DSW2行](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2450)にもfreeze参照がありません。
- P2: current-status mirrorが不完全です。[§17冒頭](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:1884)、[§18.11](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2577)、[§18.12 current-status](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2819)、[§18.13.19](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:3553)がS5a docs-freeze完了を反映していません。
確認済み事項:
- §18.16本文はdraft採択範囲と意味同一。差はレビュー用見出し注記2件と末尾区切り線の除去のみ。
- §18.2 D3-S5行自体の「S5a docs freeze complete / implementation pending」は正確。
- 既存§18.12–18.15の行は変更なし。§18.15後への追記のみです。
- `git diff`: `623 insertions / 5 deletions`。既存部5行更新＋§18.16追加を全確認し、`git diff --check`もcleanです。
P0=0 P1=3 P2=1 判定=NO-GO
所見（NO-GO）
- P1: [§18.2 D3-S6行](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2357)に、[§18.16の明示移管](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:5971)で要求された「RETIRED node自身のoutgoing successor suffix walk / chain authority」が未反映。規範上の所有範囲が閉じていません。
- P1: [§18.4](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2399)と[§18.10](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2571)がS4までのouter `10880`を最新値として残しており、§18.16のS5 `651/656`・full outer `11536`と矛盾します。
- P1: architecture mirrorが未更新です。[§18.3](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2367)にS5a same-txn specializationなし、[§18.5 category E](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2410)と[`k`表](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2424)に§18.16・`k₅=1`なし、[§18.6 DSW2行](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2450)にもfreeze参照がありません。
- P2: current-status mirrorが不完全です。[§17冒頭](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:1884)、[§18.11](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2577)、[§18.12 current-status](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:2819)、[§18.13.19](/Users/dt/job/LoRa/ninlil-fable-a3-s5/docs/17-foundation-domain-store.md:3553)がS5a docs-freeze完了を反映していません。
確認済み事項:
- §18.16本文はdraft採択範囲と意味同一。差はレビュー用見出し注記2件と末尾区切り線の除去のみ。
- §18.2 D3-S5行自体の「S5a docs freeze complete / implementation pending」は正確。
- 既存§18.12–18.15の行は変更なし。§18.15後への追記のみです。
- `git diff`: `623 insertions / 5 deletions`。既存部5行更新＋§18.16追加を全確認し、`git diff --check`もcleanです。
P0=0 P1=3 P2=1 判定=NO-GO
