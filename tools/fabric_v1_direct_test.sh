#!/usr/bin/env bash
# Deprecated alias — canonical entry is tools/run_fabric_v1_direct_tests.sh
exec "$(cd "$(dirname "$0")" && pwd)/run_fabric_v1_direct_tests.sh" "$@"
