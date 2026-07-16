# ESP32-S3 combined smoke for M3-basic adapters, Owner/Cell/loopback, and the
# durable-storage target path. This build is not physical power-cut HIL and a
# successful compile/link is not a device-runtime or field-readiness verdict.

cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ninlil_m3_combined_smoke)
