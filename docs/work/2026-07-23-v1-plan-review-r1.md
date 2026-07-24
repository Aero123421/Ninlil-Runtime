# Ninlil V1 LAB 完成計画レビュー r1

対象: `docs/work/2026-07-23-ninlil-v1-lab-plan.md` rev1  
基準: V1 は LAB 機能完成。網羅性・物理 HIL・production 認定は、それを理由に成功を偽装せず、範囲外を fail-closed にできる場合に限り V2 へ延期可能。

## 所見

### [P0-1] D3-S4..S12 と D4 を外したまま Stage 5 / restart 完成を受理できない

計画は項目 1 で Stage 5 recovery writer と restart E2E の完成を要求する一方、D3-S4..S12 を V2 に延期している（対象計画 17, 32 行）。現行正本は「S1 単独を D3 complete / Stage 5 complete に置換しない」「D4 operation 別 convergence 以降を writer に接続する」と定め（`docs/16-foundation-implementation-plan.md:100`）、さらに `Stage5 no D3 bind until S12` と明記する（`docs/17-foundation-domain-store.md:5750`）。旧 master plan も D3-S5..S12 の後に Stage 5 D3 bind と D4 commit-unknown convergence を置いていた（`docs/work/2026-07-21-master-plan.md:23-24`）。現計画には、この依存を置換する V1 用の閉じた durable schema、unsupported-state gate、operation 別 COMMIT_UNKNOWN 収束規則がない。

是正案: 次のいずれかを項目 1 の受入条件として固定する。

1. D3-S4..S12 と、V1 が実行する全 mutation の D4 convergence を V1 に戻す。
2. V1-LAB durable profile を record kind・state・operation の allowlist として固定し、D3-S1..S3 で完全検証できない row/state を writer が生成せず、recovery が publication 前に必ず拒否する。項目 2〜9 が allowlist 外を生成しない構造 gate、unknown/corrupt/mixed/COMMIT_UNKNOWN の restart 負例、成功 evidence 0 を受入条件にする。D4 は V1 allowlist 内 operation 分だけ実装する。

### [P0-2] Secure wire の context lifecycle が片方向 fresh Hop install で途切れる

項目 8 は T1c から counter/nonce/AEAD/replay/W1/L1 へ進むが、E2E context install、送受両方向 context、restart 後の resume/re-provisioning を列挙していない（対象計画 24 行）。T1c 正本の対象は Hop 一方向 fresh install だけであり、E2E install、same-context resume、M5、counter/AEAD/replay、W1/L1 を明示的に含まない（`docs/34-r7-t1c-authenticated-hop-fresh-install-owner.md:16-17`, `:123-128`）。ALL_PROPOSED 回復後は M5 等まで DORMANT であり、同 token/secret の再注入は禁止される（同 `:755-771`）。このままでは secure DATA/ACK の双方向経路と secure restart が閉じない。

是正案: 項目 7/8 に V1-LAB context lifecycle を追加する。最低限、Hop/E2E の送受方向、DATA/ACK lane、freshness/epoch fence、counter burn、replay state、clean restart、COMMIT_UNKNOWN restart の遷移を閉じる。M5 の必要 subset を実装するか、restart 時は必ず fresh M4 handshake へ戻り、旧 context を fence して nonce/key を再利用しない代替遷移を正本化する。両 endpoint の restart E2E を受入条件にする。

### [P0-3] 10 項目を一つの LAB E2E に接続する最終 gate がない

項目 5 の E2E は 2-process loopback bearer であり、項目 7〜9 より前に置かれている（対象計画 21, 40-42 行）。項目 9 は USB/radio の host simulation を要求するが、Runtime/application capability から secure wire、USB Cell Agent、R9 radio path、受信側 admission/evidence までを一つの実行で通す受入条件がない。全項目に「E2E 接続」と書くだけでは経路の topology と bypass 禁止を固定しないため、loopback E2E と独立した wire/USB/radio test が全て green でも、LAB vertical は未接続のまま成立する。

是正案: 項目 10 の前に統合 gate を追加する。少なくとも host 上で次を一つの topology として通す。

`public submit -> family/admission/reservation -> durable queue -> USB Controller/Cell Agent software path -> W1/L1 AEAD -> R9 host SPI/radio simulation -> peer RX auth/replay -> dedup/service delivery -> durable evidence -> authenticated ACK/Receipt -> source outcome`

同じ gate で ACK loss、data duplicate、reorder/replay、timeout、retry budget 枯渇、各 process restart、CRC fault、auth fault、storage fault を注入し、false success 0、bounded termination、範囲外 fail-closed を確認する。test-only direct loopback/bypass symbolがこの gate の成功経路へ入らない structural check も置く。

### [P0-4] wire fragmentation 延期に対する V1 の admission 上限がなく、BoundedTransfer が閉じない

項目 4/6 は logical fragment capability と BoundedTransfer を V1 に残し、完全 wire fragmentation/reassembly/custody は V2 に延期する（対象計画 20, 22, 33 行）。BoundedTransfer の正本は chunk/fragment を bearer 内部表現とし、pause/resume/abort を有限に保持する（`docs/02-application-contracts.md:119-135`）。一方、現行 U6 single-frame profile は payload 上限 926 bytes で、超過時は OFFER 自体を生成せず local reject とする（`docs/26-u6-transport-custody.md:99-109`）。現計画には bearer ごとの V1 logical payload 上限、経路選択、上限超過時の非受理規則がない。

是正案: 完全 wire fragmentation を V2 に残す場合、V1 の各 bearer に exact single-frame/application 上限を固定し、上限内だけを admit する。超過は ownership 取得・transaction 作成・partial write・success evidence を全て 0 にして `REJECTED`、または実装済み別 bearer への決定的 route にする。`max-1/max/max+1`、再起動、partial-apply=0 を統合 E2E で実証する。上限を満たせない BoundedTransfer use case を V1 完成項目から外す場合は、その family/profile を unsupported として public に明示する。

### [P0-5] ESP durable success と HIL 延期の境界が false-success 禁止を満たさない

項目 1 は ESP dual-slot 候補の完成昇格と restart E2E を掲げ、項目 3/9 は ESP target build・host 検証に留めて物理 HIL を残件とする（対象計画 17, 19, 25 行）。現行 custody 正本は、power-cut HIL attestation のない ESP flash では FULL success/ACCEPT/ownership release を禁止し、COMMIT_UNKNOWN または明示 reject に限定する（`docs/26-u6-transport-custody.md:408-430`）。target build と host simulation はこの attestation を代替しない。現計画は V1 RC で ESP success を禁止する gate を明記していない。

是正案: V1 の成功可能な durable E2E を POSIX SQLite に限定する。ESP は HIL attestation がない build では FULL/custody success、positive ACK/Receipt、payload release を構造的に発行不能とし、exact reject または COMMIT_UNKNOWN へ閉じる。ESP success symbol/call path 0 の link/source gateと、readback 一致でも success へ昇格しない負例を受入条件にする。「ESP provider 完成昇格」は software implementation 完了と fail-closed availability 判定に限定し、durability attested の意味では使わない。

### [P0-6] 3-lane の acceptance 順に未表現の hard dependency がある

Lane A は項目 5 の E2E 骨格まで項目 4 と独立に進み、Lane C は項目 7 から開始して最後に Lane A/B4 と合流する記述である（対象計画 39-43 行）。しかし、項目 5 が実証する priority/deadline/retry は項目 4 の本経路に依存する。項目 7/8 の M4/T1c は項目 1 の durable recovery と項目 3 の entropy/clock/storage/origin-authorization/crypto provider ownership に依存する。項目 9 の U5/U6/R9 software path は storage、Runtime delivery、secure wire、LAB profile/permit gate に依存する。また、項目 10 の LAB_ONLY enforcement は R9 の送信可能化より前の依存であり、packaging と同じ最終工程には置けない。これらの merge barrier がなく、lane 単独 candidate を完成受理できる順序になっている。

是正案: 並列作業は pure codec/model/fixture に限定し、完成受理には次の barrier を置く。

- `1 + 2 + 3 -> 7 -> 8`
- `1 + 2 + 3 + 4 -> 5`
- 項目 10 を `10a LAB_ONLY enforcement` と `10b packaging/docs/RC` に分割する
- `1 + 2 + 3 + 4 + 7 + 8 + 10a -> 9`
- `5 + 6 + 9 -> P0-3 の統合 E2E -> 10b`

各 barrier 前は candidate とし、stub/fake provider/test credential を通る経路を完成扱いしない。

### [P1-1] B5-LAB の「基本経路」が family 固有の最小機能を固定していない

項目 6 は複数 family を列挙するが、LatestState の stale generation 非適用、MeasurementBatch の retention/aggregation、ConfigRevision の stage/validate/commit/rollback、target 別 Outcome/aggregate の最小受入条件がない。正常系一件だけでも文言上は「基本経路」を満たせる。counter-offer は生成/保存を V1 に残す一方、明示同意による acceptance を V2 に送っている。M1a 正本のように reserved/unsupported とする規則（`docs/02-application-contracts.md:293-308`）とも一致していない。

是正案: family ごとの最小状態遷移と負例を表にする。counter-offer acceptance を実装しないなら V1 は生成もせず reserved/unsupported とし、生成を残すなら acceptance/cancel/restart の一貫性まで V1 に含める。

### [P1-2] ESP provider の「主要 provider」が閉集合でない

項目 3 は POSIX では全 provider を対象にするが、ESP は「主要 provider」の host 検証としか定義しない。Runtime 初期化に必須な provider と optional provider、LAB で unavailable を許す provider、production/test factory の区別がないため、未接続 provider が残っても受入判定できない。

是正案: platform provider 全 catalog に対し `implemented / LAB unavailable fail-closed / V2`、factory、owner、shutdown、restart、fault test、target link の行を持つ matrix を受入 artifact にする。`LAB unavailable` は Runtime init または該当 admission で明示 reject し、stub success を許さない。

### [P1-3] LAB_ONLY enforcement の対象 frame 集合が省略されている

項目 10 は LAB_ONLY enforcement を要求するが、旧 master plan が明示した beacon/Join/ACK/retry/diagnostics を含む全 frame の sole-edge gate（`docs/work/2026-07-21-master-plan.md:40`）を引き継いでいない。項目 9 の R1..R9 closure だけでは、V1 で実装する control frame の exact set と permit bypass 0 の受入条件が読めない。

是正案: V1 が送信可能な全 frame type の exact-set manifest を作り、各 type が R5 bind -> R2 permit -> R1 consume -> R9 SPI の sole edge を通る link/call-graph gateを置く。範囲外 profile、期限切れ assignment、clock uncertainty、permit failure は SPI TX 0 とする。

### [P1-4] Packaging 完成条件が Apache-2.0 表示に留まる

項目 10 の packaging は Apache-2.0 とだけ記載され、旧計画にあった LICENSE/NOTICE、third-party license、SBOM、外部 consumer の install/export/subproject conformance が受入条件から落ちている（`docs/work/2026-07-21-master-plan.md:46`）。

是正案: V1 RC の配布物 manifest、LICENSE/NOTICE/third-party notices、再現可能な consumer build/install smoke を必須にする。SBOM/signingを V2 に送る場合は V1 RC の非主張として明記する。

P0=6 P1=4 判定=NO-GO
