# M3-prep ESP-IDF component review

日付: 2026-07-16  
対象: ESP-IDF component packaging / ESP32-S3 compile smoke  
判定: **ESP-IDF CI greenを条件とするGO**（P0/P1なし）

## 確認結果

- host buildとESP-IDF componentは、10個のproduction private sourceを単一のCMake authorityから参照する。
- portable sourceはESP-IDF、FreeRTOS、POSIX固有headerをincludeしない。
- ESP-IDFは`v5.5.3`へ固定し、version file、component metadata、workflow、文書のdriftをhost CTestで検出する。
- workflowは公式`espressif/idf:v5.5.3` imageで`esp32s3` targetのsmoke appをbuildする。
- host Debug CTest 88/88 pass。
- tests-OFF `ninlil_runtime_private` build、DSR2 source gate、Stage 5 source gate、packaging gate/self-test、`git diff --check`はpass。

## 未実証とmerge条件

このMacではDocker daemonと`idf.py`を利用できないため、ESP32-S3 cross compileはGitHub Actionsで証明する。`.github/workflows/esp-idf.yml`の成功をmerge条件とする。

## 非主張

本変更はM3-prepであり、NVS storage、FreeRTOS owner task、USB、Wi-Fi、SX1262、Cell Agent、HIL、M3/V1完了を主張しない。
