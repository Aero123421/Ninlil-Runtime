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
2. downlink owner assignmentを次のexact tupleでfenceする。

   ```text
   authority_id
   controller_term
   assignment_epoch
   owner_controller_id
   owner_cell_id
   direction
   e2e_context_id
   key_generation
   e2e_security_id
   e2e_security_epoch
   e2e_binding_digest
   ```

   `e2e_context_generation`のような曖昧な合成fieldは使わない。tupleの不明、同値競合、後退、
   binding/direction不一致、期限切れではdownlink seal 0とする。
3. owner変更は次のexact順序とする。

   1. new E2E context tupleを**INACTIVE**でFULL installする。seal/TX 0
   2. old ownerのfresh-seal fenceをFULL commitする。fence proofはold ownerのauthenticated
      acknowledgmentまたはauthorityが証明したold lease expiryのどちらかをcopy-ownする
   3. new owner assignmentとnew contextを1 atomic FULLでACTIVEにする
   4. new ownerへtrafficをswitchする
   5. bounded receive-only retirement window後にold contextをretireする

   step 2完了前にnew contextをACTIVEにせず、step 3後にold ownerが新規sealしてはならない。
   同一E2E sealer stateを複数独立Controllerで共有しない。
4. old ownerがfence前にseal済みだが未送信のblobはburn済みcounterを戻さずdiscardし、
   same transaction + new attemptでnew contextへ再prepareする。fence前に物理送信済みのblobだけを
   bounded receive-only retirement/dedupe対象にできる。old contextで再送・新規sealせず、
   duplicate application effectを起こさない。必要なreply/evidenceはnew assignment/context上の
   new attemptとして送る。
5. uplink duplicateはstable transaction/event identity、attempt identity、content digestと、
   exact context tuple
   `{e2e_context_id, key_generation, e2e_binding_digest}`でControllerがdeduplicateする。
   曖昧な`context generation`は使わない。first receiveだけを唯一の発生事実とみなさず、
   全path evidenceをbounded diagnosticsとして保持できる。late/replay判定も同じexact tupleへ
   bindする。
6. parent switchによるretryはsame transaction identity + new attempt identityとする。
   old/new parentからのlate packetを同じattemptとしてmergeしない。
7. parent setはimmutable revision/digestを持ち、eligible、primary、backup、receive-only、
   owner candidate、cell/channel、leaseを表現する。Fabric path policyはこのrevisionをsnapshotする。
8. **redundancy profile**と**capacity split profile**を別profileにする。前者は同一uplinkの複数受信、
   後者はservice/trafficごとのowner/cell分割であり、N+1 capacityなしに同一SLOを保証しない。
9. backhaul loss、parent RF loss、Controller lossを別health signalとして扱う。
   local availabilityだけでownerへ昇格せず、fenced authority assignmentを要する。
10. parent assignment store schema 1候補はparent set revision、authority fence、owner、
    上記exact E2E tuple、INACTIVE/ACTIVE/receive-only/retired state、fresh-seal fence proof、
    lease、migration stateをcanonicalに保存する。
   COMMIT_UNKNOWNまたはmigration中はdownlinkをfenceする。
11. parent数、candidate/path evidence、duplicate window、migration inflight、retired context、
    metricsをprofileでboundedにする。exhaustion時はownerを二重化せず、新規migrationを拒否する。

## Compatibilityとmigration

- NRW1 `0x11`、E2E context semantics、route terminal invariantは変更しない。
- multi-parentはcritical negotiated capabilityとする。非対応Endpointをreceive-diversityへ
  silent参加させない。
- single-parent deploymentはparent set size 1として同じmodelを使える。
- rolling migrationはDecision 3のINACTIVE install → old fresh-seal fence/proof → atomic ACTIVE →
  switch → retirement順を変えない。途中失敗時にownerを推測しない。
- Runtime Platform ABIは変更せず、Fabric/management APIへparent/path diagnosticsを公開する。

## Dependencies

ADR-0017 Fabric、NRW1 full state、ADR-0019 route authority/lease/drain、
durable E2E context install、Controller dedupeを前提とする。Relay acceptance前に
Multi-parentをproduction機能と呼ばない。

## Acceptance

1. 2 parent + 1 Endpointでduplicate uplink dedupe、全path evidence、duplicate effect 0
2. owner loss、parent RF loss、backhaul loss、Controller restart、Endpoint restart
3. split brain/unknown owner/stale term/binding・direction不一致でdownlink seal 0
4. INACTIVE FULL → old fresh-seal fence proof FULL → atomic ACTIVE → switch → retireの全境界と、
   step 2前後のcrashで同時sealer 0
5. old sealed unsent discard/new attempt、already-sent receive-only dedupe、old-context再送/seal 0
6. same transaction/new attempt migration、exact context tupleに基づくold context replay/late packet rejection
7. capacity splitとredundancy profileを別load testで測定
8. assignment store全write point crash、COMMIT_UNKNOWN、schema migration
9. 100-node multi-cell simulator、queue/resource exhaustion、N+1不足の明示
10. 2 parent + EndpointのESP/RF HIL、forced failover、24h soak
11. mixed version、rolling update、operator diagnostics/runbook、independent review

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
