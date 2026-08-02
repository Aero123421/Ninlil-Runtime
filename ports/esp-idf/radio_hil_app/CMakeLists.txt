cmake_minimum_required(VERSION 3.16)

# ESP32-S3 + SX1262 radio composition (R4 bus + R9 phy). Build ≠ RF HIL PASS.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ninlil_radio_hil)
