# Minimal ESP-IDF project that compiles the ninlil component for ESP32-S3.
# M3-prep build evidence only — not HIL, storage port, or Cell Agent.

cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ninlil_m3_prep_smoke)
