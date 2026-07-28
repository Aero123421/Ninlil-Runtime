# ADR-0019: Route Authority and Relay Lifecycle

状態: **Proposed — docs-only（implementation / acceptance pending）**  
提案日: 2026-07-28  
受入日: —（未受入）

## Context

[30章](../30-r6-secure-radio-wire.md)はNRW1のroute handle、lease/fence検査、Hop
open/rewrap、E2E envelope不変、forwarding resourceをAccepted仕様として固定している。
しかしControllerによるroute計算・発行、Cell Agentへのinstall、durable recovery、drain、
operator diagnosticsを接続するlifecycle/APIは未実装である。

## Decision

1. [30章](../30-r6-secure-radio-wire.md)のbyte/security/resource semanticsを唯一の正本とし、
   本ADRは変更しない。Relay専用message kindを追加せず、同章のnon-zero route handleモデルを使う。
2. Controllerをroute authorityとするが、Controllerの**management/install record**と
   [30章](../30-r6-secure-radio-wire.md)の**exact NRW1 route record**を別typeとして扱う。
   management recordは
   `authority_id16 + controller_term_u64 + route_revision_u64 + lease_epoch_u64 +
   authority_clock_epoch_id16 + lease_expiry_ms_u64`でfenceし、zeroと`UINT64_MAX`を
   term/revision/epoch/expiryに許可しない。
   別名`route_epoch`は作らず、management `lease_epoch`をmaterialized NRW1 recordの
   `lease_epoch`へ同値copyする。Cell Agent/Relayは独自にdurable routeを発行・延長しない。
   authorityごとのprecedenceは`controller_term`、次に`route_revision`のunsigned numeric順とする。
   後退をrejectし、同一term/revisionでcanonical record digestが異なる場合はauthority conflictとして
   そのauthorityの全routeをfenceする。同一digest retryだけをidempotentとして許可する。
3. management keyは
   `{ingress_hop_context_id_u32, route_handle_u16, route_generation_u16}` exactとし、全fieldを
   non-zero/非MAXにする。これはdocs/30のroute lookup keyそのものであり、valueだけに隠したり
   `ingress_hop_context_id`を省略してはならない。install ownerは1 local FULL atomic
   materializationで、このkeyとmanagement valueからdocs/30 exact fields
   `egress_peer_id16`、`egress_hop_context_id_u32`、`egress_route_handle_u16`、
   `egress_route_generation_u16`、`authority_id16`、`lease_epoch_u64`、
   `expiry_u64`、`grant_id16`、`queue_quota_entries_u16`、`queue_quota_bytes_u32`、
   `max_hops_u8`、`ack_policy_u8`を欠落なく生成する。
   `queue_quota_entries`は1..64、`queue_quota_bytes`は1..16320、`max_hops`は1..8
   （ESP V1 profile default/maximumは3）、
   `ack_policy`は`0=NO_LINK_ACK`または`1=REQUEST_LINK_ACK`だけとする。terminal next hopだけは
   egress route handle/generationを両方0、それ以外は両方non-zero/非MAXとする。
   `controller_term/route_revision`はmanagement-only fenceであり、NRW1 route recordの
   wire/exact fieldへ追加しない。
4. materialized exact recordと同じatomic unitへR2 sidecar
   `{clock_epoch_id[16], expiry_ms_u64}`をbindする。sidecar `expiry_ms`はdocs/30 record
   `expiry`とexact一致し、R2 accepted clock epochと一致する場合だけACTIVE/forward候補にできる。
   authority ID、lease epoch、clock epoch、expiryの不一致/後退/不明では
   ACTIVE 0、queue admission 0、forward 0、radio TX 0とする。
5. route lifecycleを`STAGED -> ACTIVE -> DRAINING -> EXPIRED -> RETIRED`のclosed setとする。
   STAGEDはforward不可。各ACTIVE routeは`next_admission_seq_u64`（初期1、MAX到達でroute fence）を
   持ち、forward queue itemへadmission時の`admission_seq + route_revision + absolute_deadline`
   をcopy-ownする。DRAININGへ入るFULL recordはimmutable
   `{drain_fence_u64=next_admission_seq, route_revision_u64,
   drain_deadline_ms_u64, lease_deadline_ms_u64}`を持つ。
   許可できるのは`admission_seq < drain_fence`、同一route revision、かつ
   `min(item_deadline, drain_deadline_ms, lease_deadline_ms)`より前に完了可能なbounded
   inflightだけである。完了可能性はchecked-addで
   `now + remaining_attempts * (max_airtime_ms + turnaround_ms +
   link_ack_wait_ms) + scheduler_guard_ms`を計算し、FRAGでは全remaining link groupsについて
   同じ項を合算する。profile snapshotに値が無い、overflow、deadline超過ならforward/TX 0。
   新規admission、別revision、deadline超過はforward/TX 0。deadline到達後は全forward/TX 0とする。
6. planned removalはdescendant assessment、alternate path staging、new admission fence FULL、
   bounded eligible inflight drain、retirement evidenceの順とする。sudden failureはlease expiryと
   Controller再計算で扱い、alternate routeなしを成功表示しない。
7. Relayはouter Hopを認証後にのみroute lookupし、E2E envelopeを開かず、
   [30章](../30-r6-secure-radio-wire.md)どおりbit-identical E2E bytesを次Hopへrewrapする。
8. route APIはFabricのopaque management API候補とし、install batch、activate、drain、
   retire、query、bounded diagnosticsを提供する。Runtime Platform ABIは変更しない。
9. route store schema 1候補は既存Runtime/control namespaceへ行単位に追加せず、別物理partitionの
   **Fabric storage domain**に置く。このdomainはESP physical format 4を再利用し、production
   2 namespaceの一方を`ninlil.route.v1`、他方をADR-0020 parent assignment用に予約する。
   これにより既存Runtime namespace、`ninlil.ctl.v1`の32-key budget、同一partitionのwear budgetを
   暗黙共有しない。

   128 routeは`route_handle`順の8-slot固定page × 16ページへmaterializeする。physical keyは
   directory/header 1件とpage最大16件だけで、namespace上限32 keyを超えない。page内各slotは
   lookup key、management record、materialized exact record、R2 sidecar、drain fence/stateを
   logical type分離してcanonical big-endianで保持する。空slotはcanonical zeroであり、
   tombstone/occupiedと区別する。page valueは4096 bytes以下、各record/pageはmagic4、
   schema_u16=1、record_length_u16、page index/generation、occupied bitmap、reserved zero、
   CRC32Cを持つ。volatile radio handle、pointer、queue slotを保存しない。

   同一handleの異なる`ingress_hop_context_id/route_generation`が同時存在し得るため、
   page slotを`route_handle mod 128`だけで一意化しない。SPEC_ACCEPTED時に固定する
   deterministic bounded placement/probeまたはController割当規則は、最大128件で必ず停止し、
   key三つ組の衝突を別routeへ上書きしない。install/materializationとbatch replacementはFULL
   atomic、COMMIT_UNKNOWN時は該当pageと参照routeをforward fenceしてrecoveryする。
   1 batchはroute 8件以下、directoryと最大8 touched pageを含むlogical storage mutation 9件以下とし、上限を
   分割して部分成功にしない。
10. forwarding queue、route records、children、per-route inflight、retry/airtime reservationは
   Hardware/Runtime profileでboundedにする。exhaustion時は新規forward/admissionを拒否し、
   既存reserved control/safety capacityを横取りしない。
11. 各RF transmitはrouteの有効性だけでなく既存TxPermit/compliance sole authorityを通す。
    route leaseは送信許可ではない。

## Compatibilityとmigration

- NRW1 `wire_profile_id=0x11`は不変。byte、timer、resource意味を変更する場合は新profile IDを要する。
- route store schemaはFoundation schema、N6 schema、ESP physical format 4と別domainにする。
- route非対応peerはcritical capability negotiationでattach拒否し、direct routeへsilent変換しない。
- rolling updateはControllerが新旧capabilityを理解した後、Cell Agent単位でrouteをdrainして行う。
- schema migration中またはowner不明時は対象routeをACTIVEにしない。

## Dependencies

M1a restart-safe kernel、M3 durable storage、ADR-0017 Fabric、M7 scheduler、
NRW1 LINK/FRAG/state implementationを前提とする。Multi-parentは本ADRのroute lease、
drain、fencing acceptance後に進める。

## Acceptance

### SPEC_ACCEPTED（実装開始を許可する設計gate）

次をすべて満たした時点で本ADRを設計決定としてAcceptedにできる。これはRelayの実装済み、
target対応、production supportを意味しない。

1. public Fabric route APIの関数signature、opaque handle lifecycle、borrow/copy ownership、
   callback/reentrancy、batch結果、status precedenceをexactに固定
2. management/materialized/R2 sidecar/drain logical record、directory、16 page、8 slotの
   key/valueをoffset/byte数まで固定し、magic、schema、length、reserved、CRC32C、
   deterministic placement/probe、最大record/key数、migration/recoveryをKAT化
3. docs/30のroute field、R2 clock、U5 authorityとの対応表に未対応・重複fieldが0
4. Controller authority precedence、同値digest conflict、drain完了可能性、batch atomicityを
   独立reference modelとcross-language vectorで再計算
5. storage/RAM/queue/airtime/timerのexact target profileがESP32-S3で静的に成立する見積りと、
   全exhaustion時のfail-closed結果を固定
6. compatibility、rolling migration、unknown schema、NRW1 profile不変を独立reviewで承認

### RELEASE_SUPPORTED（100%完成を許可するrelease gate）

SPEC_ACCEPTED後の実装について、次をすべて満たす。

1. 2〜3 hopのloss/duplicate/reorder、loop、stale/expired/conflicting lease
2. management recordからdocs/30全exact field + R2 sidecarのatomic materialization KAT。
   ingress lookup key欠落/差替え、field欠落/差替え、authority/lease/clock epoch不一致、
   same-term/revision digest conflictでACTIVE/forward/TX 0
3. install/activate/drain/retire全write pointのcrash、COMMIT_UNKNOWN、Controller/Relay restart
4. Relay E2E bytes bit-identical oracle、outer Hopだけopen/rewrap
5. forwarding queue/route table/airtime exhaustionとreserved capacity保護
6. admission sequenceのwrap、drain fence前後、same/different revision、worst-case completion式の
   checked-add overflow、drain/lease/item deadline境界、deadline後TX 0
7. planned drain、sudden failure、sleepy descendant、alternate routeなし
8. 100-node deterministic topology simulationと24h host soak
9. 3台以上のESP32-S3/SX1262 RF HIL、各hop TxPermit evidence、24h soak
10. mixed version、rolling update、diagnostics/runbook、independent review
11. batch 8 routes/9 logical mutationsの境界と10 mutation拒否、16 page/128 route満杯、
    placement衝突、部分materialization 0

## Consequences

route byte semanticsを変えず、設置・撤去・障害時のRelay lifecycleを管理できる。
代わりにController authority、durable route store、bounded forwarding queue、
topology simulator、複数実機HILが必要になる。

## Rejected alternatives

- Relayが受信品質だけで恒久routeを自己発行する
- expired routeでbest-effort forwardする
- E2E payloadをRelayで復号・変換する
- drainなしにroute recordを削除する
- route leaseをTxPermitとして扱う

## 非主張

本ADRはProposed docs-onlyであり、route/Relay実装、NRW1 full、RF HIL、SLO、legal、
production meshを主張しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [Identity and Join](../03-identity-and-join.md)
- [ADR-0017](0017-bearer-registry-path-selection.md)
- [ADR-0020](0020-multi-parent.md)
