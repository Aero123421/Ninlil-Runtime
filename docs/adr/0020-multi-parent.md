# ADR-0020: Multi-parent Ownership, Diversity and Failover

状態: **Proposed — docs-only（implementation / acceptance pending）**  
提案日: 2026-07-28  
受入日: —（未受入）

## Context

複数parentは受信冗長化とcell容量分割を可能にするが、uplink重複とdownlink split brainを
同じ仕組みで扱えない。[03章](../03-identity-and-join.md)は複数parent uplink、
single downlink owner、transaction identityを維持したparent switchを定義し、
[30章](../30-r6-secure-radio-wire.md)はE2E sealerとcontext generationのHA invariantを固定する。
parent registry、assignment、failover lifecycle、実装APIは未完成である。

## Decision

1. **Receive diversity**と**Transmit ownership**を分離する。Endpoint uplinkはpolicyで許可された
   複数parentが受信できるが、downlinkをsealできるownerは常に最大1つとする。
2. downlink ownerはNode全体の単一roleではなく、immutableな`owner_scope_id[16]`ごとに
   割り当てる。scope IDは
   `SHA-256(ASCII("NINLIL-OWNER-SCOPE-V1") || endpoint_runtime_id16 ||
   direction_u8 || namespace_len_u16_be || namespace ||
   service_len_u16_be || service || traffic_class_u16_be ||
   path_policy_id16)[0..15]`で導出する。`path_policy_id`はNFL1の
   `route_policy_id`とbit-exact同一である。`endpoint_runtime_id`とtraffic classは
   ADR-0017 path policy recordのclosed `scope_endpoint_selector`と`traffic_class`から取得する。
   selectorはoriginal APPLICATIONのsourceまたはtarget Runtime IDだけを選び、device/
   installation IDの有無から推測しない。reverse kindはingress triggerにFULL保存した
   original endpoint/scopeを使い、反転後のtargetから再導出しない。local priorityやBearer
   metricsからtraffic classを推測しない。
   namespace/serviceの各lengthは1..63、direction/traffic classはclosed
   enum、reserved値はrejectする。単純な可変長連結は使わない。同じscopeでは最大1 owner、
   異なるscopeでは別owner/cellへcapacity splitできる。downlink owner assignmentを次の
   exact tupleでfenceする。

   ```text
   owner_scope_id
   authority_id
   controller_term
   assignment_epoch
   assignment_revision
   owner_controller_id
   owner_cell_id
   direction
   e2e_context_id
   key_generation
   e2e_security_id
   e2e_security_epoch
   e2e_binding_digest
   authority_clock_epoch_id
   lease_not_after_authority_ms
   handoff_token_digest
   ```

   `e2e_context_generation`のような曖昧な合成fieldは使わない。tupleの不明、同値競合、後退、
   binding/direction/scope不一致、期限切れではdownlink seal 0とする。
3. 複数PC/Controller/Endpointにまたがるowner変更を、単一Storage transactionでatomicと
   主張してはならない。authorityが発行する一回限りのhandoff tokenと、次のdistributed
   state machineを使う。各矢印はそのparticipantのlocal FULL commitであり、唯一の
   linearization pointは`AUTHORITY_COMMITTED`へのauthority compare-and-swapである。

   ```text
   PREPARED_NEW
     -> OLD_FENCED_PROOF
     -> AUTHORITY_COMMITTED
     -> NEW_OWNER_ACTIVATED
     -> ENDPOINT_OBSERVED
     -> OLD_RETIRED
   ```

   - `PREPARED_NEW`: new ownerがnew E2E context tupleとtoken digestをINACTIVEで保存する。
     seal/TXは0。
   - `OLD_FENCED_PROOF`: old ownerがlocal fresh-seal fenceをFULL commitし、authorityへ
     authenticated proofを返す。またはauthority自身が、同じclock epoch内でold lease expiryを
     durableに観測してexpiry proofを作る。単なる通信断やlocal wall clockはproofにならない。
   - `AUTHORITY_COMMITTED`: authorityはcurrent assignment revision、old tuple、token unusedを
     compare-and-swapし、new tupleを唯一のcurrent assignmentにする。失敗・同値競合・
     COMMIT_UNKNOWNではnew owner activation 0。
   - `NEW_OWNER_ACTIVATED`: new ownerはauthority commit receiptを検証・FULL保存し、
     tokenを一回だけconsumeしてnew contextをACTIVEにする。
   - `ENDPOINT_OBSERVED`: Endpoint/parent routingがnew assignmentを観測する。これは
     authorityのlinearization pointではなく、new owner activationの前提にも代替にもならない。
   - `OLD_RETIRED`: bounded receive-only window後、old contextとproofをretire/tombstone化する。

   old fence/expiry proofが成立するまでauthorityはcommitしてはならず、authority commit receiptが
   無いnew ownerはACTIVEになれない。同じ`handoff_token_digest`の再利用、別scope/term/revisionへの
   転用、rollbackは拒否する。timeout/retryは同じtokenとstateをidempotently再照会し、状態を
   推測して飛び越えない。同一E2E sealer stateを複数独立Controllerで共有しない。
4. 各participantは`handoff_token_digest + owner_scope_id + old/new exact tuple +
   local_state + authority_commit_digest + proof_digest`をdurableにcopy-ownする。
   `COMMIT_UNKNOWN`ではold/new候補をread-classifyし、次のstateを推測しない。
   Authorityはused-token tombstoneを少なくともold/new context retirement完了まで保持する。
5. old ownerがfence前にseal済みだが未送信のblobはburn済みcounterを戻さずdiscardし、
   same transaction + new attemptでnew contextへ再prepareする。fence前に物理送信済みのblobだけを
   bounded receive-only retirement/dedupe対象にできる。old contextで再送・新規sealせず、
   duplicate application effectを起こさない。必要なreply/evidenceはnew assignment/context上の
   new attemptとして送る。
6. uplink duplicateはstable transaction/event identity、attempt identity、content digestと、
   exact context tuple
   `{e2e_context_id, key_generation, e2e_binding_digest}`でControllerがdeduplicateする。
   曖昧な`context generation`は使わない。first receiveだけを唯一の発生事実とみなさず、
   全path evidenceをbounded diagnosticsとして保持できる。late/replay判定も同じexact tupleへ
   bindする。application callback/effect ownerも`owner_scope_id + assignment_revision`で唯一にし、
   non-owner Controllerはevidenceをauthority/current ownerへ転送するだけでeffectをpublishしない。
7. parent switchによるretryはsame transaction identity + new attempt identityとする。
   old/new parentからのlate packetを同じattemptとしてmergeしない。
8. parent setはimmutable revision/digestを持ち、eligible、primary、backup、receive-only、
   owner candidate、cell/channel、leaseを表現する。Fabric path policyはこのrevisionをsnapshotする。
9. **redundancy profile**と**capacity split profile**を別profileにする。前者は同一uplinkの複数受信、
   後者はservice/trafficごとのowner/cell分割であり、N+1 capacityなしに同一SLOを保証しない。
10. ESP32-S3 + SX1262の1-radio nodeは異なるLoRa channelを同時受信できない。parent setは
    `same-channel diversity`、またはControllerが発行するbounded `scheduled-scan`のどちらかを
    明示し、後者はchannelごとのreceive window、guard、sleep/wake、miss budgetをprofileで固定する。
    availabilityだけで「同時待受」を主張しない。
11. backhaul loss、parent RF loss、Controller lossを別health signalとして扱う。
   local availabilityだけでownerへ昇格せず、fenced authority assignmentを要する。
12. parent assignment store schema 1候補はADR-0019と同じ別物理Fabric storage domainの
    第2 production namespace `ninlil.parent.v1`に置き、既存Runtime/control partitionとwear
    budgetを共有しない。parent set revision、owner scope、authority fence、
    上記exact E2E tuple、PREPARED_NEWからOLD_RETIREDまでのlocal state、fresh-seal/expiry proof、
    handoff token/used-token tombstone、authority commit receipt、leaseをtype/key分離してcanonicalに
    保存する。namespaceはheader 1、assignment page最大8、token/tombstone page最大8の
    合計17 key以下とし、各page 4096 bytes以下、全key/value配置と最大scope/token件数は
    SPEC_ACCEPTEDで固定する。COMMIT_UNKNOWNまたはmigration中はdownlinkをfenceする。
13. parent数、candidate/path evidence、duplicate window、migration inflight、retired context、
    metricsをprofileでboundedにする。exhaustion時はownerを二重化せず、新規migrationを拒否する。

## Compatibilityとmigration

- NRW1 `0x11`、E2E context semantics、route terminal invariantは変更しない。
- multi-parentはcritical negotiated capabilityとする。非対応Endpointをreceive-diversityへ
  silent参加させない。
- single-parent deploymentはparent set size 1として同じmodelを使える。
- rolling migrationはDecision 3のPREPARED_NEW → OLD_FENCED_PROOF →
  AUTHORITY_COMMITTED → NEW_OWNER_ACTIVATED → ENDPOINT_OBSERVED → OLD_RETIREDの順を
  変えない。途中失敗時にownerを推測しない。
- Runtime Platform ABIは変更せず、Fabric/management APIへparent/path diagnosticsを公開する。

## Dependencies

ADR-0017 Fabric、NRW1 full state、ADR-0019 route authority/lease/drain、
durable E2E context install、Controller dedupeを前提とする。さらに[03章](../03-identity-and-join.md)
の「1 site = 1 active Site Controller writer」を、single logical authority writer +
複数fenced Controller participantへ拡張するAccepted authority protocolが必要である。
このauthority protocolなしに複数PCをsupportしない。Relay acceptance前に
Multi-parentをproduction機能と呼ばない。

## Acceptance

### SPEC_ACCEPTED（実装開始を許可する設計gate）

次をすべて満たした時点で本ADRを設計決定としてAcceptedにできる。これはMulti-parent、
複数PC HA、target対応、production supportを意味しない。

1. owner scope derivation、parent set、assignment tuple、handoff token/proof/receipt/tombstoneの
   canonical byte layoutとdigest domainをoffset/byte数まで固定
2. authority compare-and-swap API、各participant API、retry/query/reconcile結果、ownership、
   reentrancy、status precedenceをexactに固定
3. PREPARED_NEWからOLD_RETIREDまでの状態遷移、各local FULL write、authority linearization、
   COMMIT_UNKNOWN recoveryを独立distributed modelで検証
4. single logical authority writer + 複数fenced participantへの03章拡張を同じAccepted trancheで
   固定し、network partition時のsafety/liveness境界を明記
5. parent/assignment storageの全key/value layout、record上限、retention、migrationと、
   same-channel/scheduled-scanのresource/timer profileを固定
6. duplicate effect ownerとdownlink sealerが全状態で最大1になるmachine-checkable invariant、
   互換性、rolling update、独立reviewを承認

### RELEASE_SUPPORTED（100%完成を許可するrelease gate）

SPEC_ACCEPTED後の実装について、次をすべて満たす。

1. 2 parent + 1 Endpointでduplicate uplink dedupe、全path evidence、duplicate effect 0
2. owner loss、parent RF loss、backhaul loss、Controller restart、Endpoint restart
3. split brain/unknown owner/stale term/binding・direction不一致でdownlink seal 0
4. distributed handoff全6 state、各local FULL write point、authority CAS、token replay/
   cross-scope reuse、各boundary crashで同時sealer 0
5. old sealed unsent discard/new attempt、already-sent receive-only dedupe、old-context再送/seal 0
6. same transaction/new attempt migration、exact context tupleに基づくold context replay/late packet rejection
7. capacity splitとredundancy profileを別load testで測定
8. assignment store全write point crash、COMMIT_UNKNOWN、schema migration
9. 100-node multi-cell simulator、queue/resource exhaustion、N+1不足の明示
10. 2 parent + EndpointのESP/RF HIL、forced failover、24h soak
11. mixed version、rolling update、operator diagnostics/runbook、independent review
12. 同一channel diversityとscheduled multi-channel scanを別試験にし、1-radioで同時待受を
    誤って成功表示しない

## Consequences

複数親機を容量と冗長性の両方へ利用できる一方、single-owner fence、E2E context rotation、
duplicate evidence、authority storageが必須になる。単に同じ鍵を複数親機へ配る設計は採用しない。

## Rejected alternatives

- first heard parentが自動でdownlink ownerになる
- 複数Controllerが同じE2E sealer/contextを共有する
- parent切替ごとに新transactionを作る
- redundancyとcapacity splitを同じSLOとして扱う
- split brain時にbest-effort downlinkを送る

## 非主張

本ADRはProposed docs-onlyであり、Multi-parent、HA、split-brain recovery、RF HIL、
capacity/SLO、production supportを主張しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [Identity and Join](../03-identity-and-join.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [ADR-0019](0019-route-relay.md)
