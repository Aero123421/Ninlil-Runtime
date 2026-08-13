# OSS review: Runtime step single epilogue

日付: 2026-08-13

## 対象

原レビュー250–256行 / OR-22は、`ninlil_runtime_step()`が`in_step`を立てた後に
7つのreturn pathで個別clearしていたため、将来のreturn追加がRuntimeを恒久的な
`NINLIL_E_REENTRANT`へ残す構造を指摘した。

Normativeなowner/re-entry precedenceは[Foundation C ABI](../12-foundation-abi.md)の
public execution contractを正本とし、public ABI、wire、storageは変更しない。

## 実装

`src/runtime/runtime_public.c`は、outer validation後に`in_step=1`へ入り、以後の全statusを
`step_exit`へ集約する。normal fallthroughも明示`goto step_exit`とし、epilogueは
`in_step=0`、phase IDLE、health projection、蓄積statusのreturnをexact 1回行う。

`tools/runtime_step_epilogue_gate.py`はCMakeが選んだHost C compilerでdefault、test target、
all-private test target、およびconfigured `ninlil_runtime_private`の4 profileをpreprocessし、
実targetのcompile definition、macro、conditional compilation、C11 translation phase 1/2と
alternative punctuatorを反映した後のfunction definitionをbrace-matchして次を閉じる。

- budget guard直後にunconditional `in_step=1`→phase CLOCKがあり、手前のgoto/labelで
  entryを迂回できない。`in_step=1`、`step_exit`、`in_step=0`が各exact 1件。
- set / label / clearがfunction top-levelにあり、normal path末尾も`goto step_exit`である。
- set後の全`goto`が`step_exit`だけを指し、唯一のpost-entry `return`がclosed epilogue末尾の
  `return status`である。既知のnonlocal process/thread exitも拒否する。
- clear削除・重複・条件化・`#if 0`化、plain/line-splice/trigraph-splice/macro early return、
  alternate label、final status改変、nonlocal exit、conditional/digraph/label entry迂回、
  test-definition限定macro return、entry後の追加clear/decrement、alias receiverからのclearを
  含む17 mutationを全profile個別にRED化する。test-definition限定macro returnは、
  macroがinactiveのdefaultでGREEN、activeなtest/configured profileでREDとなる1 conditional
  matrixを別に固定する。function body内で
  明示された`in_step` member accessはentryとepilogueのclosed pair以外を許可しない。

## Behavioral evidence

`v1_runtime_delivery`のcallback/Storage/Clock fault matrixは、最初のstepがStorage、
commit-unknown、clock-uncertain、degraded等で終了した直後に同じRuntimeへもう一度stepし、
期待するReducer statusを要求する。`in_step`が残れば2回目は`NINLIL_E_REENTRANT`となるため、
これはfailure path後のowner-state回復を直接検証する。

Focused verification:

```text
python3 tools/runtime_step_epilogue_gate.py check
python3 tools/runtime_step_epilogue_gate.py self-test
ctest --test-dir <normal> -R '^v1_runtime_delivery$' --output-on-failure
ctest --test-dir <asan> -R '^v1_runtime_delivery$' --output-on-failure
```

## 非claim

単一epilogueはstep内部の全protocol semantics、全Port failure、または一般old-epoch
Recovery Fenceを証明しない。また任意のcallee内部に隠されたstate mutationやnonlocal
transferまではこのbounded lexical gateで静的証明しない。
それらは各Runtime testとXR-01で別に追跡する。
