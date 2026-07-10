# ADR-0001: Project Boundary and First Release

状態: Accepted<br>
決定日: 2026-07-10

## Context

KGuard向けに作成した`linkos/`の3台lab実装は、短期間の実機確認には有用ですが、KGuard固有message、wire、保存、controller処理が近く、他applicationが安全に再利用できるpublic contractではありません。

一方、NinlilはKGuardだけでなく、表示、漏水、occupancy、計測、設定、有限object転送などを、複数bearerと有限資源の上で扱える独立Runtime/SDKを目標にします。

## Decision

1. 公開project名を **Ninlil Runtime** とする。
2. `ninlil/`をNinlilの仕様、新実装、公開互換性判断の正本とする。
3. KGuardは最初のreference applicationとし、依存方向を`KGuard -> Ninlil public API`だけにする。
4. `productv1/docs/99-decision-log.md`はKGuard側の採用・移行判断を記録する。Ninlil自体の仕様判断は本ADR directoryへ記録する。
5. 現行`linkos/`は **Legacy LinkOS Lab v1** として凍結する。golden vector、hardware adapter、receipt動作等の選択移植元にはできるが、NinlilのAPI、wire、storageとの互換性は保証しない。
6. 最初の新実装はPOSIX上のrestart-safe Generic Transaction Kernelである。実radioやKGuard schemaを最初のcoreへ入れない。
7. 最初の実装単位をM1aとし、単一targetの`DesiredStateCommand`と`EventFact`、durable admission、idempotency、receipt、deadline、crash recovery、deterministic simulatorに絞る。

## Consequences

- Ninlil contributorはKGuardのdecision logを読まなくてもcoreを実装・利用できる。
- KGuard固有のQR、画面文言、現場policy、schemaはintegration profile側に残る。
- Legacy labとの互換を理由に、初回public ABIやwireを固定しない。
- group、counter-offer、selector、production identity/radioは、M1aの不変条件を壊さず後続releaseで追加する。
- KGuard validationはM1a exit gate完了後のsoftware-only `TEST` laneから開始し、M1bおよびM2〜M5と並走できる。PC + USB Cell Agent + Display + Leak + SX1262のphysical `LAB` laneはM3のESP-IDF/Cell AgentとM5のLAB Tx Gate/radioの必要subset完了後に限る。どちらもexperimental adapterとして隔離し、Ninlil conformanceの代わりにしない。

## Related decisions

- KGuard側の採用判断: `productv1/docs/99-decision-log.md` D-041
- D-041はKGuard repository内でD-040の名称、正本、最初の実装範囲をsupersedeする。
