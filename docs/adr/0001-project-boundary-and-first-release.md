# ADR-0001: Project Boundary and First Release

状態: Accepted<br>
決定日: 2026-07-10

## Context

`linkos/`の3台lab実装は、短期間の実機確認には有用ですが、application-specific message、wire、保存、controller処理が密結合しており、他applicationが安全に再利用できるpublic contractではありません。

Ninlilは、command、event、state、計測、設定、有限object転送などを、複数bearerと有限資源の上で扱える独立Runtime/SDKを目標にします。

## Decision

1. 公開project名を **Ninlil Runtime** とする。
2. `ninlil/`をNinlilの仕様、新実装、公開互換性判断の正本とする。
3. Reference applicationはNinlil public APIだけに依存し、Ninlil Coreから個別integrationへは依存しない。
4. Ninlil自体の仕様判断は本ADR directoryへ記録する。個別integrationの採用・移行判断はNinlilのnormative仕様から分離する。
5. 現行`linkos/`は **Legacy LinkOS Lab v1** として凍結する。golden vector、hardware adapter、receipt動作等の選択移植元にはできるが、NinlilのAPI、wire、storageとの互換性は保証しない。
6. 最初の新実装はPOSIX上のrestart-safe Generic Transaction Kernelである。実radioやapplication-specific schemaを最初のcoreへ入れない。
7. 最初の実装単位をM1aとし、単一targetの`DesiredStateCommand`と`EventFact`、durable admission、idempotency、receipt、deadline、crash recovery、deterministic simulatorに絞る。

## Consequences

- Ninlil contributorは外部製品のrepositoryやdecision logを読まなくてもcoreを実装・利用できる。
- Domain固有のprovisioning手順、UI文言、運用policy、schemaはintegration profile側に残る。
- Legacy labとの互換を理由に、初回public ABIやwireを固定しない。
- group、counter-offer、selector、production identity/radioは、M1aの不変条件を壊さず後続releaseで追加する。
- Reference application validationはM1a exit gate完了後のsoftware-only `TEST` laneから開始し、M1bおよびM2〜M5と並走できる。PC + USB Cell Agent + command/event Endpoints + SX1262のphysical `LAB` laneはM3のESP-IDF/Cell AgentとM5のLAB Tx Gate/radioの必要subset完了後に限る。どちらもexperimental adapterとして隔離し、Ninlil conformanceの代わりにしない。

## Related decisions

- [Project Charter](../00-project-charter.md)
- [Roadmap](../09-roadmap.md)
