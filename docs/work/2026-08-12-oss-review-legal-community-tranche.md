# OSS review: legal / community boundary tranche

日付: 2026-08-12

## 対象と結論

Project ReviewのOR-09とOR-33だけを対象に、repository内で事実を確定できる範囲を
実装した。OR-09のrepository内作業とOR-33のbadgeは完了し、残件は外部authorityだけである。
全first-party C/HのSPDX、source license inventory、DCO sign-off経路、DCO workflowのimmutable authority、既存CI badgeは
code内で閉じた。一方、正式copyright holder/yearとGitHub admin設定はowner判断が
必要なため、推測・変更していない。

| 項目 | 判定 | 根拠 / 残件 |
| --- | --- | --- |
| OR-09: source license inventory | CLOSED | `dependency-inventory.json`がfirst-party defaultを`Apache-2.0`、license textを`LICENSE`、copyrightを`NOASSERTION`、`tools/_vendor`をPyYAML inventoryへ除外対応する |
| OR-09: installed public header SPDX | CLOSED | `include/ninlil/*.h` 10/10の先頭行をexact `SPDX-License-Identifier: Apache-2.0`とし、既存third-party gateが集合・値を閉じる |
| OR-09: repository全C/H fileの個別SPDX | CLOSED | review基準の799本と本trancheで追加された13本を合わせた現行first-party C/H 812/812に先頭行のApache-2.0 SPDX identifierを付与。`tools/_vendor`は依存inventoryへ分離し、gateがtracked/untracked実集合と欠落mutationを検査する |
| OR-09: DCO 1.1経路 | CLOSED (code) | `CONTRIBUTING.md`に`git commit -s`、修正・local checkを記載。workflowは各commitのauthor emailとsign-off emailを照合する |
| OR-09: holder/year、required check / App | EXTERNAL | 下記owner/legal判断が未完。`LICENSE` Appendixと`NOTICE`のholder行は未変更 |
| OR-33: CI badge | CLOSED (code) | canonical repository、`ci.yml`、default branch `main`へ固定したGitHub native badgeだけを追加し、workflow gateがREADMEとCI triggerを照合する |
| OR-33: description / topics / Discussions | EXTERNAL | 現在はdescription空、topics未設定、Discussions無効。推奨値とowner実行案を下記へ分離した |

## 実装

- 既存`third_party_notice_gate.py`へfirst-party license scope、公開header 10本のexact SPDX、
  および現行first-party C/H実集合812本のfirst-line SPDX検査を追加した。vendored PyYAMLのpath / inventory ID対応もclosed objectで固定し、
  holder未確定をSPDX標準の`NOASSERTION`として保持した。新しいlicense frameworkは作っていない。
  既存release SBOMもproject packageの`copyrightText`をこのinventory値へ結び、推測値を拒否する。
- [DCO 1.1](https://developercertificate.org/)のsign-off手順を`CONTRIBUTING.md`へ追加した。
  `tools/dco_signoff_gate.py`はmerge-baseからPR headまでの各commitを読み、validな
  `Signed-off-by: Name <email>`とcommit author emailの一致を検査する。
- `.github/workflows/dco.yml`は`pull_request`、`contents: read`だけで動き、remote Actionを
  full commit SHAへ固定する。さらにPR head上の変更可能なgateを直接実行せず、eventの
  base SHAから`tools/dco_signoff_gate.py`を抽出してself-testとrange checkを実行する。
  この方式の導入順序も境界の一部であり、workflowを含むPRを開く前に、gate scriptだけを
  target branchへ先行配置する。baseにscriptがない状態でworkflowを先に実行すると
  `git show BASE_SHA:tools/dco_signoff_gate.py`は必ず失敗するため、その状態をgreenとは
  主張しない。
- 既存`release_workflow_identity_gate.py`がDCO trigger、permission、runner、strict shell、
  checkout ref/history、base/head event SHA、base-controlled gate command、remote Action job
  配置をsemantic YAMLで照合する。floating Action、head-controlled gate、range check削除を
  self-testで拒否する。既存のordered release authorityにもDCO self-testを追加した。
- READMEにはGitHub native CI badgeだけを追加した。CodeQL、coverage、release、HILのbadgeは
  remote evidenceが確立していないため追加していない。2026-08-12のread-only確認では、
  `main`の最新CI runはcommit `9cc907fe3a384aba9bf0e984b62fa55fa1207f3f`でsuccessだった。
  badgeはlive状態を表示するもので、将来のgreenやrelease supportを恒久的に主張しない。

## 外部blockerとowner向け実行案

### 1. Copyright holder / year

**blocker:** 正式な権利者のlegal nameと、記載すべき最初のyearまたはyear rangeをrepositoryの
内容から確定できない。GitHub account / repository owner名をcopyright holderとみなすことは
できない。

ownerまたはlegal担当が次の2値を明示した後だけ、`NOTICE`へそのexact stringを追加する。

```text
Copyright <VERIFIED_YEAR_OR_RANGE> <VERIFIED_LEGAL_HOLDER>
```

Apache-2.0本文末尾の`Copyright [yyyy] [name of copyright owner]`はlicense適用方法を示す
Appendix templateなので、holder通知先として編集しない。確認値がない現状では`NOTICE`も
変更しない。

### 2. DCO required check / GitHub App

**blocker:** workflow fileを追加しても、branch rulesetのrequired check化やGitHub App installは
repository admin権限とownerの運用判断が必要である。この権限状態はcodeから証明できない。

推奨は、最初のremote PRでworkflow名`DCO sign-off`、job名`Sign-off trailers`の成功を確認後、
そのrunで観測したcheck contextを`main`対象rulesetのrequired checkにすること。UI上の表示名は
`DCO sign-off / Sign-off trailers`を想定するが、raw contextは最初のrunを見ずに推測しない。
変更前のread-only確認案（`<PR_NUMBER>`と`<HEAD_SHA>`は実値へ置換）:

```sh
gh run list --repo Aero123421/Ninlil-Runtime --workflow dco.yml --limit 5
gh pr checks <PR_NUMBER> --repo Aero123421/Ninlil-Runtime
gh api repos/Aero123421/Ninlil-Runtime/commits/<HEAD_SHA>/check-runs \
  --jq '.check_runs[] | {name,app:.app.slug,conclusion}'
gh api repos/Aero123421/Ninlil-Runtime/rulesets
```

blindなbranch-protection PUTは既存policyを上書きし得るため行わない。ownerがGitHub提供外の
App運用を選ぶ場合は[official DCO App listing](https://github.com/apps/dco)を確認してinstallする。
既存workflowをrequiredにするかAppを使うかはownerが一方をauthorityとして決め、二重で異なる
判定を持たせない。

### 3. Repository metadata / Discussions

2026-08-12に`gh repo view`で確認した状態は、public、default branch `main`、description空、
topics未設定、Discussions無効だった。推奨値とowner実行案は次のとおり。

```sh
gh repo edit Aero123421/Ninlil-Runtime \
  --description 'Portable C11 runtime/SDK for durable, evidence-aware communication over intermittent LoRa, Wi-Fi, and USB links.'
gh repo edit Aero123421/Ninlil-Runtime \
  --add-topic c --add-topic c11 --add-topic embedded --add-topic iot \
  --add-topic lora --add-topic wifi --add-topic usb --add-topic runtime \
  --add-topic sdk --add-topic offline-first
gh repo edit Aero123421/Ninlil-Runtime --enable-discussions
gh repo view Aero123421/Ninlil-Runtime \
  --json description,repositoryTopics,hasDiscussionsEnabled,defaultBranchRef
```

これらはrepository公開面を変えるため、このtrancheでは実行していない。Discussionsを有効にする
場合は、`CODE_OF_CONDUCT.md`と`SUPPORT.md`の既存境界に沿ったcategory / moderation担当もownerが
同時に決める。

## 検証

- `python3 tools/third_party_notice_gate.py check` / `self-test` — PASS
- first-party C/H SPDX coverage — 812/812、非public sourceのfirst-line削除mutation RED
- `python3 tools/dco_signoff_gate.py self-test` — PASS
- `python3 tools/release_workflow_identity_gate.py check` / `self-test` — PASS
- `python3 tools/spdx_release_sbom.py self-test` — PASS
- `python3 tools/release_distribution_authority_gate.py self-test` — PASS
- DCO synthetic Git range（signed positive / unsigned negative）— PASS
- actionlint 1.7.12（official checksum照合後、全workflow）— PASS
- public header C11/C++17 self-contained smoke（10 header × 2）— 20/20 PASS
- public headerをcomment除去して`HEAD`と比較 — 宣言・定数差分0（10/10）
- ABI golden / public layout — 2/2 PASS
- Markdown links、JSON parse、Python compile、`git diff --check` — PASS
- `git diff --exit-code -- LICENSE NOTICE` — PASS（変更なし）

`.DS_Store`、`dist/`、Apache `LICENSE` Appendix、`NOTICE`のholder/yearは変更せず、
stage / commit / push、GitHub設定変更も行っていない。
