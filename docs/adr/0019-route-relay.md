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
   `authority_id + controller_term + route_revision + lease_epoch + lease_expiry_ms`でfenceする。
   別名`route_epoch`は作らず、management `lease_epoch`をmaterialized NRW1 recordの
   `lease_epoch`へ同値copyする。Cell Agent/Relayは独自にdurable routeを発行・延長しない。
3. install ownerは1 FULL atomic materializationで、management recordからdocs/30 exact fields
   `egress_peer_id`、`egress_hop_context_id`、`egress_route_handle`、
   `egress_route_generation`、`authority_id`、`lease_epoch`、`expiry`、`grant`、
   `queue_quota`、`max_hops`、`ack_policy`を欠落なく生成する。
   `controller_term/route_revision`はmanagement-only fenceであり、NRW1 route recordの
   wire/exact fieldへ追加しない。
4. materialized exact recordと同じatomic unitへR2 sidecar
   `{clock_epoch_id[16], expiry_ms_u64}`をbindする。sidecar `expiry_ms`はdocs/30 record
   `expiry`とexact一致し、R2 accepted clock epochと一致する場合だけACTIVE/forward候補にできる。
   authority ID、lease epoch、clock epoch、expiryの不一致/後退/不明では
   ACTIVE 0、queue admission 0、forward 0、radio TX 0とする。
5. route lifecycleを`STAGED -> ACTIVE -> DRAINING -> EXPIRED -> RETIRED`のclosed setとする。
   STAGEDはforward不可。DRAININGへ入るFULL recordはimmutable
   `{drain_fence, route_revision, drain_deadline_ms, lease_deadline_ms}`を持つ。
   許可できるのはdrain fenceより前にadmit済み、同一route revision、かつ
   `min(drain_deadline_ms, lease_deadline_ms)`より前に完了可能なbounded inflightだけである。
   新規admission、別revision、deadline超過はforward/TX 0。deadline到達後は全forward/TX 0とする。
6. planned removalはdescendant assessment、alternate path staging、new admission fence FULL、
   bounded eligible inflight drain、retirement evidenceの順とする。sudden failureはlease expiryと
   Controller再計算で扱い、alternate routeなしを成功表示しない。
7. Relayはouter Hopを認証後にのみroute lookupし、E2E envelopeを開かず、
   [30章](../30-r6-secure-radio-wire.md)どおりbit-identical E2E bytesを次Hopへrewrapする。
8. route APIはFabricのopaque management API候補とし、install batch、activate、drain、
   retire、query、bounded diagnosticsを提供する。Runtime Platform ABIは変更しない。
9. route store schema 1候補はmanagement record、materialized exact record、R2 sidecar、
   drain fence/stateをtype/key分離してcanonicalに保存する。volatile radio handle、pointer、
   queue slotを保存しない。install/materializationとbatch replacementはFULL atomic、
   COMMIT_UNKNOWN時はforwardをfenceしてrecoveryする。
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

1. 2〜3 hopのloss/duplicate/reorder、loop、stale/expired/conflicting lease
2. management recordからdocs/30全exact field + R2 sidecarのatomic materialization KAT。
   field欠落/差替え、authority/lease/clock epoch不一致でACTIVE/forward/TX 0
3. install/activate/drain/retire全write pointのcrash、COMMIT_UNKNOWN、Controller/Relay restart
4. Relay E2E bytes bit-identical oracle、outer Hopだけopen/rewrap
5. forwarding queue/route table/airtime exhaustionとreserved capacity保護
6. drain fence前後、same/different revision、drain/lease deadline境界、deadline後TX 0
7. planned drain、sudden failure、sleepy descendant、alternate routeなし
8. 100-node deterministic topology simulationと24h host soak
9. 3台以上のESP32-S3/SX1262 RF HIL、各hop TxPermit evidence、24h soak
10. mixed version、rolling update、diagnostics/runbook、independent review

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
