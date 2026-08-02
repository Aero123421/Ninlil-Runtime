# 2026-07-30 Host completion integrated E2E independent review

状態: **Host completion closure re-review GO — P0=0 / P1=0 / P2=0**

実行日: 2026-07-30 JST  
対象: Host Wi-Fi + Fabric + RRMP + MFDT integrated E2E  
基準HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`

この記録は、旧fixtureがRRMP Authority v2のcommit/activateを完了せず
`DRAIN_FENCED`になっていた問題と、84 KiBを超えるlogical RRMP exportを
単一65,536-byte上限のstorage valueとして扱っていた問題に対する修正を、
独立に再監査した結果である。レビュー担当は修正実装を担当しておらず、
本レビューではproduction codeとtestを変更していない。Grok Build、Qwen、
Cursor、Claudeは使用していない。

対象はdirty shared workspace上の未commit候補であるため、HEADだけでは内容を
再現できない。主要authorityのSHA-256を次に固定する。

| Authority | SHA-256 |
| --- | --- |
| `tests/host/host_completion_integrated_e2e.c` | `799532908c3ca0814cca97cd217f4ad5fa5c5c7a31f658371e2d2db7f3f11865` |
| `tools/host_completion_integrated_e2e.sh` | `1fd91ddac380341a02bc3120ab3e78a76d8de4b4874409ba79fc304f208fb965` |
| `tests/support/host_completion_wire.c` | `7e9033e17698649bd09d9aca3f0fc5bc659e6b6effb3bf5a6da02318ea951fd3` |
| `tests/runtime/route_relay_v1/rrmp_test_common.h` | `b74ac771ae512ea77f5c137a504bf7c5b9108584ef39d18aeeabcc992e3b2e51` |
| `src/runtime/route_relay_v1/rrmp_core.c` | `01b125a847e7c6655ed102e05e84adcdd87a154eef9b064fc737503200cf6e6b` |
| `src/transport/wifi_v1/wifi_session.c` | `f6c895c7a70e214b617cbed2d7aa94db85d068a2849c7ab141719229fb84b02a` |
| `src/transport/wifi_v1/wifi_attachment_m4.c` | `084895a18aa4338e17a579a3ef1c4f97a73dffe90db3f08106b72ad953348e69` |
| `tools/wifi_v1_gen_test_certs.sh` | `66a1342cf5f2aeda6fbce094f7026ccb55a78204254ca13a48a9dccd26b71de1` |
| `docs/adr/0019-route-relay.md` | `dabf5771a1a2bcedb70449b388642caf3c69c79a0a91e67b831201a3b377dc24` |
| `docs/adr/0020-multi-parent.md` | `23adab9897c983bff0fdd413aab65beabe016f2a558c22d472dc487e4b8c4821` |

## Verdict

| Severity | Open findings |
| --- | ---: |
| P0 | **0** |
| P1 | **0** |
| P2 | **0** |

Authority bootstrap、fence、物理storage分割、fresh-owner recoveryにproduction
contractを弱める欠陥は見つからなかった。独立再実行もnormal / ASan+UBSanを
2回連続で完走した。

初回reviewでは、shell gateがP1 parent側の実受信をpositive assertionにせず、
background childのsanitizer異常と終了statusもfail条件にしていないP1と、
ephemeral portのTOCTOU P2を検出し、`P0=0 / P1=1 / P2=1 NO-GO`とした。
後述のclosure repairとnegative self-testで両件を閉じた。

## Authority / fence review

`host_completion_integrated_e2e.c:885-972`のbootstrapは、storage bind後に
次の順序を通る。

1. canonical NOA1を作る。
2. v2 prepareを本番`ninlil_parent_owner_prepare_v2()`へ渡す。
3. 初回authority用のvacuous fence proofを生成する。
4. 現在のRRM1 bundle witnessをplatform storageから読む。
5. witness、expected old/new tuple、CAS generationを含むcommit digestを作り、
   本番`ninlil_parent_authority_commit_v2()`へ渡す。
6. commit receiptを本番`ninlil_parent_owner_activate()`へ渡す。

fixture helperは入力構築とdigest構築だけを担当し、owner内部の
`downlink_tx`、seal-capable flag、scope lifecycleを直接書き換えない。
routeも`host_completion_integrated_e2e.c:346-401`でinstall後に
本番activateを通る。従って旧fixtureのようにauthority commit/activateを省略して
`DRAIN_FENCED`を回避するためproduction fenceを緩めた修正ではない。

P1→P2の切替はattempt 1のexact parent A、attempt 2のexact parent Bを本番
selectionで確認した後、Fabricの選択先とRRMP outbound providerをP2へ切り替える
（`host_completion_integrated_e2e.c:1544-1627`）。`parent_loss`を呼ばない理由も、
そのAPIがscopeをsealして以後のadmitを閉じる現行契約と一致する。

## Physical storage bundle and cold recovery

ADR-0019 §8.8とproduction `rrmp_core.c:3050-3370`は次を固定する。

- manifest: exact key `RRMP/M1`、exact 256 bytes
- chunks: exact key `RRMP/C0`..`RRMP/C4`
- chunk value: 最大61,440 bytes
- logical bundle: 最大307,200 bytes
- unused chunk key: absent
- recovery: point readとprefix iteratorのclosed-key-setを相互照合し、
  missing、extra、duplicate、non-canonical order、unused-but-presentを拒否

test serializer（`host_completion_integrated_e2e.c:685-833`）はlogical exportを
1 valueへ再包装せず、platform iteratorから得た物理rowを
`key_length + value_length + exact key + exact value`として保存する。
各valueは`NINLIL_M1A_MAX_STORAGE_VALUE_BYTES`以下でなければexport/importとも失敗する。
import後は本番`ninlil_rrmp_owner_storage_recover()`が上記closed-key-set、
RRM1 CRC、chunk length、chunk digest、logical digestを再検証するため、
test serializerの緩い入力だけでLIVEへ進むことはできない。

実測relay durable artifactは**104,654 bytes**であり、65,536-byte単一valueではない。
復旧経路（`host_completion_integrated_e2e.c:1630-1800`）は次を実行する。

1. 本番FULL commit。
2. 物理rowをfile bytesへexport。
3. 旧ownerをfiniし、旧handleをclose、旧storageをdestroy。
4. 両workspaceをzero。
5. file bytesをfresh storageへimport。
6. 別workspace上のfresh ownerをinitし、本番storage recovery。
7. LIVE route、attempt-2 fence、cold後の新しいhopを確認。

旧ownerや旧storage objectをfresh ownerへcopyしていない。pre-crashの`scope`値、
transport session、outbound providerは照会・I/Oの外部入力として再bindされるが、
route lifecycle、parent attempt fence、queue/custody stateの復旧authorityには使われない。

MFDT sender側も
`host_completion_integrated_e2e.c:2156-2253`で旧engine、pipeline、
workspace、storeを全zeroにした後、fileからnew storeへimportし、
new engine init → `restart_scan_transfer()` → sender rehydrateだけで続行する。
実測durable bytesは2,705、cold後のphase/geometryと最終digestが一致した。

## Wi-Fi credential and real-path review

証明できた範囲:

- ephemeral P-256 mutual-auth PKIを毎run生成
- leafのcritical OID bindingからclient/server runtime、authority、termを取得
- caller supplied peer inputはleaf identityとのexact一致を要求
- TLS post-handshake acceptance後にのみPEER_SESSIONへ進む
- M4 membership、credential candidate、attachment、Fabric registryをFULL storage
  recordからload/classify
- owner-minted single-use M4 evidenceとsession authority mintを経由
- exporter2でATTACHED session idを生成
- P2は実NWB1/NFL1/NCL1を受信し、MFDT publication exactly onceまで完了

従って、以前のstatus 16を単に無視してP2だけ成功扱いにする経路ではない。
現在のASan logにも`P1: ATTACHED`、`P1: hop_frame`、
`P2: ATTACHED`、複数`P2: ncl1_frame`、P2 publicationが存在した。

非claim:

- このscenarioはHost Labのephemeral PKIとin-memory M4 provisioningである。
- `ninlil_wifi_session_require_credentials(..., 1)`を使うcredential rotation /
  committed secret-ref pathはこのscenarioの対象外。
- Controller/CAのproduction provisioning、secure element、real APは証明しない。

## Independent execution

実行コマンド:

```sh
bash tools/host_completion_integrated_e2e.sh
bash tools/host_completion_integrated_e2e.sh
```

2回とも結果:

```text
scenario strict: PASS digest=6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e
scenario asan: PASS digest=6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e
host_completion_integrated_e2e: ALL PASS
```

| Evidence | Result |
| --- | --- |
| strict C11 `-Wall -Wextra -Werror -pedantic -Wvla` | **PASS ×2** |
| AddressSanitizer + UndefinedBehaviorSanitizer endpoint run | **PASS ×2** |
| endpoint digest | exact same `6823a37f…c4951e` ×4 scenarios |
| P1 client submit / observed current log | `p1_sub>=1` / `P1: hop_frame` present |
| P2 client submit / receiver processing | `p2_sub>=1` / `P2: ncl1_frame>=4` |
| P2 durable publication | exact 1 |
| endpoint ↔ P2 digest | exact equal |
| duplicate custody | no increment |
| orphan process after run | 0 |
| private key under persistent `last-logs` | 0 |
| remaining `run-*` certificate directory | 0 |

`ASAN_OPTIONS`は`detect_leaks=0`であり、LeakSanitizer evidenceは主張しない。

## Findings

### P1-1（CLOSED）: background roleの実受信・sanitizer failureをshell gateがfail-closedにしていない

根拠:

- `tools/host_completion_integrated_e2e.sh:226-245`はrelay側の
  `p1_sub>=1` / `p2_sub>=1`だけを要求する。
- `p1_sub`は`host_completion_wire.c:392-403`でclient sessionのsendが
  acceptedになった時点で増える。P1 serverがframeをparseした証拠ではない。
- P1 logは`PUBLICATION_ONCE`が**ない**ことしか検査されず、
  `P1: ATTACHED`と`P1: hop_frame`はpositive requirementではない。
- `tools/host_completion_integrated_e2e.sh:201-207`はbackground P1/P2/relayを
  killし、全wait statusを`|| true`で捨てる。
- ASan scenario後も4つのlogから
  `AddressSanitizer` / `UndefinedBehaviorSanitizer` / `runtime error:`
  を拒否する検査がない。

影響:

P1 serverがattach後にsanitizer findingで終了しても、relayのsocket writeが先に
acceptedされれば`p1_sub>=1`を満たし得る。required markerを既に出したbackground
roleのsanitizer異常も、終了statusとlogの両方が無視される。この状態では
`scenario asan: PASS`を全roleのsanitizer-clean evidenceとして扱えない。

必要な修正:

1. P1 exact `ATTACHED`と1回以上の`hop_frame`を必須にする。
2. P2 exact `ATTACHED`、1回以上の`hop_frame`、既存publicationを必須にする。
3. strict / ASanとも全role logをfatal/sanitizer diagnostic deny-listで検査する。
4. 通常終了を期待しないdaemon roleはsignal killを区別しつつ、kill前に既に
   abnormal exitしていた場合のstatusを保存して失敗にする。
5. 修正後にstrict / ASanを最低2回再実行し、同digestと全role markerを確認する。

### P2-1（CLOSED）: `free_port()`にbind-close-bindのTOCTOU raceがある

`tools/host_completion_integrated_e2e.sh:127-131`はPythonでephemeral portをbindし、
socketをcloseして番号だけ返した後、別processが改めてbindする。その間に他processが
portを取得できるため、並列CIでは稀なfalse REDになり得る。現行2連続runでは再現して
おらずfalse greenではない。将来はlistener自身にport 0をbindさせて実portをmarkerで
返すか、予約socketを引き渡す構造が望ましい。

## Closure repair and re-verification

closure repair後のauthority:

| Authority | SHA-256 |
| --- | --- |
| `tests/host/host_completion_integrated_e2e.c` | `a34f16fffbbf111df1b00e8b6750096110ba074f9361f4d5142562cd4956c0e3` |
| `tools/host_completion_integrated_e2e.sh` | `3d8fa2c8b820b066e403433f231be0439e97d2d614ffbb8077fb81e9300df95c` |

repairはtest fixtureとdirect gateだけに限定し、production
authority、fence、RRMP storage実装を変更していない。

### Explicit two-phase shutdown and exit authority

endpointはMFDT completionとdigest確定後、authenticated NWB1/NFL1上でexact
test-control `SHUTDOWN_V1`をrelayへ送る。relayはこれをApplicationDataとして
RRMPへforwardせず、endpointへexact ACKを返し、P1/P2へshutdownをpropagateする。
endpointはACK受信までsessionをcloseしない。P1/P2はshutdownを受信した後に、
それぞれhop-only invariantまたはpublication exactly-once invariantを検証して
自発的にexit 0する。

shell gateはendpoint、relay、P1、P2の全PIDをbounded waitし、全exit statusを
回収する。正常runではsignal killを使わない。timeout、interrupt、異常終了時だけ
trapがTERM、bounded wait、KILLの順でorphanを回収する。

### Receiver-side and sanitizer hard evidence

- P1はparsed hop envelopeごとに
  `P1: VERIFIED_HOP_FRAME seq=... count=...`を出す。
- gateはP1のexact `ATTACHED`とexact 1 verified hopを必須にする。
- P2も`ATTACHED`、verified hop、NCL1 frames、publicationを必須にする。
- relay側`p1_sub` / `p2_sub`とparent側実受信を両方要求する。
- strict / ASanの各scenarioで4 role全logを
  AddressSanitizer、UBSan、LeakSanitizer、MemorySanitizer、
  ThreadSanitizer、`runtime error:`、Sanitizer summary/errorに対してhard scanする。

### Atomic ephemeral listener

Pythonのbind-close-bind `free_port()`を削除した。P1、P2、relay自身が
`ninlil_wifi_tcp_listen_loopback(..., 0, &bound_port)`でport 0をbindし、
socketを保持したままactual portをexact markerで返す。shellはそのmarkerを
bounded waitしてから依存roleを起動するため、予約と実bindの間のTOCTOUはない。

### Positive and negative evidence

positive:

```sh
bash tools/host_completion_integrated_e2e.sh
bash tools/host_completion_integrated_e2e.sh
```

repair後に2回連続で、各runのstrict / ASanとも次を再現した。

```text
endpoint: exit_status=0
relay: exit_status=0
P1: exit_status=0
P2: exit_status=0
scenario strict: PASS digest=6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e
scenario asan: PASS digest=6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e
```

negative:

```sh
bash tools/host_completion_integrated_e2e.sh --negative-self-test
```

1つ目はP1が全protocolを正常完了した直後にwrapperでexit 97を強制する。
gateは`P1: nonzero exit_status=97`として拒否した。2つ目はASan binaryのrelay
logへ`ERROR: AddressSanitizer: injected-negative-self-test`を注入する。
全role exit 0でもlog scannerが拒否した。self-testは両方のexact injected markerが
保存logに存在することも確認してから次を返した。

```text
host_completion_integrated_e2e: NEGATIVE SELF-TEST PASS
```

終了後のfixture processと`run-*` work directoryは0だった。これにより
P1-1とP2-1はclosure re-reviewでCLOSED、current open countは
`P0=0 / P1=0 / P2=0`となる。

## Artifact and secret handling

`WORKDIR`はPID固有のtemp directoryで、trapがEXIT/INT/TERM時に削除する。
test PKIのprivate keys、CSR、durable row fileはこのdirectory内だけに置かれ、
標準出力へkey materialを出さない。終了後に`run-*` directoryとprivate-key markerが
残っていないことを確認した。

永続するのはtemp側のtest binary / dSYMと`last-logs`である。logにはloopback port、
固定test identity、frame count、digestが含まれるがprivate keyやcredential secretは
含まれない。repo内へのruntime artifact漏洩は確認しなかった。

## Physical HIL boundary

本reviewはmacOS loopback TCP + OpenSSL Host software evidenceだけである。
ESP32-S3実機boot、Wi-Fi STA/AP/DHCP、LwIP、flash/NVS power-cut、SX1262/RF、
物理relay/multi-parent、電波法・認証はすべて`NOT_RUN`である。
このreviewを`HIL_VERIFIED`または`RELEASE_SUPPORTED`へ昇格する根拠にしてはならない。

## Final recommendation

production authority/fence/storage修正そのものに回帰はなく、P1-1 / P2-1も
test-only closure repairとnegative evidenceで閉じた。従ってHost completion
integrated **software acceptanceはGO**とする。

このGOはmacOS/Linux Host software fixtureの範囲だけであり、physical HIL、
target credential provisioning、LeakSanitizer、`RELEASE_SUPPORTED`は含まない。
