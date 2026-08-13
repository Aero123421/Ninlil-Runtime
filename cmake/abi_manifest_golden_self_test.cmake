if(NOT DEFINED GOLDEN_SCRIPT)
    message(FATAL_ERROR "GOLDEN_SCRIPT not set")
endif()

set(_root "${CMAKE_BINARY_DIR}/abi_manifest_golden_self_test")
set(_goldens "${_root}/goldens")
set(_generator "${_root}/fake-generator.sh")
file(REMOVE_RECURSE "${_root}")
file(MAKE_DIRECTORY "${_goldens}")
file(WRITE "${_generator}" "#!/bin/sh\nprintf '%s\\n' 'target.id=ILP32-le-32'\n")
file(CHMOD "${_generator}" PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)

execute_process(
    COMMAND ${CMAKE_COMMAND}
        -DGEN=${_generator}
        -DGOLDEN_DIR=${_goldens}
        -P ${GOLDEN_SCRIPT}
    RESULT_VARIABLE _missing_result
)
if(_missing_result EQUAL 0)
    message(FATAL_ERROR "missing ABI golden unexpectedly passed")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND}
        -DGEN=${_generator}
        -DGOLDEN_DIR=${_goldens}
        -DNINLIL_ABI_GOLDEN_ALLOW_MISSING=ON
        -P ${GOLDEN_SCRIPT}
    RESULT_VARIABLE _allowed_result
)
if(NOT _allowed_result EQUAL 0)
    message(FATAL_ERROR "explicit ABI golden missing override failed")
endif()
