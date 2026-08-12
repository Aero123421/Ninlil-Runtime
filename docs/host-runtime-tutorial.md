# Ninlil Host Runtime first tutorial

状態: 現行 `main` の利用者向けtutorial（Informative）

このtutorialでは、source treeをbuildし、公開Runtimeのfocused integration smokeを1件
実行します。install済みpackageを別projectから使う手順は
[Host Runtime SDK](host-runtime-sdk.md)に分離しています。

## 1. 前提を確認する

LinuxまたはmacOSで、CMake 3.20以上、C11 / C++17 compiler、Python 3、Node.js 18以上、
OpenSSL 3.x、SQLite3 development packageを用意します。利用可能なversionは次で確認できます。

```bash
cmake --version
python3 --version
node --version
openssl version
```

このtutorialはHost softwareだけを検証します。物理USB/RF、実AP、flash power-cut、
production法規適合の証拠にはなりません。

## 2. Repositoryを取得する

```bash
git clone https://github.com/Aero123421/Ninlil-Runtime.git
cd Ninlil-Runtime
```

既にcheckout済みなら、そのrepository rootから次へ進みます。

## 3. Focused smokeをbuildする

```bash
cmake -S . -B build-tutorial -DCMAKE_BUILD_TYPE=Debug
cmake --build build-tutorial \
  --target ninlil_v1_integration_gate_e2e_test --parallel
```

Configureまたはbuildが失敗した場合は、その段階のerrorを先に解消します。全suiteへ広げて
原因を隠しません。CMake optionの一覧は[Build options](build-options.md)にあります。

## 4. Focused smokeを実行する

```bash
ctest --test-dir build-tutorial \
  -R '^v1_integration_gate_e2e$' --output-on-failure --no-tests=error
```

合格時は`100% tests passed`と`0 tests failed`が表示されます。これはHost上のfocused
integration pathがそのcheckoutで合格した、という意味です。全CTest、sanitizer、target build、
物理HILの合格までは意味しません。

## 5. 次の目的を選ぶ

- SDKをinstallして外部consumerから使う: [Host Runtime SDK](host-runtime-sdk.md)
- 公開targetとinstall treeを照合する: [SDK distribution manifest](sdk-distribution-manifest.md)
- transactionとevidenceを理解する: [Runtime concepts](runtime-concepts.md)
- 現在の未証明範囲を確認する: [Current status](status.md)

不要になったtutorial buildだけを削除する場合は`build-tutorial/`を削除します。source treeや
他のbuild directoryを巻き込まないでください。
