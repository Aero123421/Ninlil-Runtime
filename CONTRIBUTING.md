# Contributing to Ninlil Runtime

Ninlil Runtimeへの貢献に関心を持っていただき、ありがとうございます。このrepositoryはpre-alphaであり、実装速度よりもcontractの明確さと再現可能な検証を優先します。

## Spec-first workflow

Foundation M1aの正本は次のNormative文書です。

- [12. Foundation C ABI](docs/12-foundation-abi.md)
- [13. Foundation State Machine](docs/13-foundation-state-machine.md)
- [14. Foundation Ports and Deterministic Simulator](docs/14-foundation-ports-and-simulator.md)

仕様の穴、矛盾、観測可能な新しい判断がある場合は、実装で推測して固定せず、先に正本文書、test vector、必要なADRを更新してください。Informative文書や既存codeがNormative contractと競合する場合は、正本を優先します。

## Pull requestの範囲

- 1つのPRを、小さく独立検証できる目的へ絞ってください。
- 仕様変更、public ABI変更、実装、test、generated artifactを必要に応じて同じPRへ含めてください。
- 無関係なformat変更やrenameを混ぜないでください。
- 未実装機能に成功を返すstubを追加しないでください。未対応は規定されたerrorでfail closedにします。
- KGuardや特定hardwareの業務語彙をportable Coreへ持ち込まないでください。

## Languageとbuild requirements

- Portable Core、fixture、toolのC codeはC11です。
- Public headerはC11とC++17の両方からincludeできなければなりません。
- Compiler extensionへ依存せず、strict warningをerrorとして通してください。
- Pointer値、struct padding、host時刻、container iteration順へ決定結果を依存させないでください。
- **Building and running the test suite** requires a **Python 3** interpreter on `PATH` (used only by the independent Domain Store D1-A / D1-B1 vector oracle: `tools/domain_store_vector_gen.py generate|check`). Production libraries do not link or invoke Python.

通常buildとtest:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

ASan / UBSan:

```sh
CC=clang CXX=clang++ cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

PRを提出する前に、変更範囲に応じたtargeted testに加えて、通常suiteとsanitizer suiteを実行してください。CTest件数は増減するため、件数ではなく全test成功をgateにします。

## Public ABI changes

`include/ninlil/`の定数値、型幅、field順、function signature、ownership、nullabilityはcontractです。変更する場合は次を同時に行ってください。

1. 正本文書と、必要ならAccepted ADRで変更理由と互換性を定義する。
2. [Versioning and Compatibility](docs/06-versioning-and-compatibility.md)に従い、ABI versionと`0.x` migrationへの影響を判断する。
3. ABI manifest、registry、golden artifact、C11/C++17 smoke、negative testを更新する。
4. [CHANGELOG.md](CHANGELOG.md)のUnreleasedへ利用者影響を記録する。

既存ABIへfieldを黙って追加する、enum値を再利用する、provider固有errorをpublic statusへcastする変更は受け入れません。

## Documentation and tests

- 新しいobservable behaviorにはpositive、boundary、failure testを追加してください。
- Failureやcommit-unknownをsuccessへ丸めないことを検査してください。
- Markdown linkとcommandがrepository rootから有効であることを確認してください。
- 実装済み、planned、experimental、unsupportedを明確に分け、完成していないhardware/security/complianceを完成済みと記載しないでください。

## Reporting security issues

機密性のある脆弱性情報はpublic issueへ投稿せず、[Security Policy](SECURITY.md)のprivate reporting手順を使用してください。
