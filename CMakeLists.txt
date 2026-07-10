cmake_minimum_required(VERSION 3.16)

project(ninlil VERSION 0.1.0 LANGUAGES C CXX)

add_library(ninlil INTERFACE)
target_include_directories(ninlil INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    enable_testing()

    set(NINLIL_STRICT_C_FLAGS
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -pedantic-errors
    )
    set(NINLIL_STRICT_CXX_FLAGS
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -pedantic-errors
    )

    function(ninlil_apply_strict_warnings target)
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:${NINLIL_STRICT_C_FLAGS}>
            $<$<COMPILE_LANGUAGE:CXX>:${NINLIL_STRICT_CXX_FLAGS}>
        )
    endfunction()

    add_executable(ninlil_smoke_c11 tests/smoke/c_consumer.c)
    target_link_libraries(ninlil_smoke_c11 PRIVATE ninlil)
    set_target_properties(ninlil_smoke_c11 PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_smoke_c11)

    add_executable(ninlil_smoke_cxx17 tests/smoke/cxx_consumer.cpp)
    target_link_libraries(ninlil_smoke_cxx17 PRIVATE ninlil)
    target_compile_features(ninlil_smoke_cxx17 PRIVATE cxx_std_17)
    ninlil_apply_strict_warnings(ninlil_smoke_cxx17)

    add_test(NAME smoke_c11 COMMAND ninlil_smoke_c11)
    add_test(NAME smoke_cxx17 COMMAND ninlil_smoke_cxx17)

    set(NINLIL_PUBLIC_HEADERS version platform service transaction runtime)
    foreach(_header IN LISTS NINLIL_PUBLIC_HEADERS)
        set(_c_source "${CMAKE_CURRENT_BINARY_DIR}/self_contained_${_header}_c11.c")
        file(WRITE "${_c_source}"
            "#include <ninlil/${_header}.h>\n"
            "int main(void) { return 0; }\n"
        )
        set(_c_target "ninlil_self_contained_${_header}_c11")
        add_executable(${_c_target} "${_c_source}")
        target_link_libraries(${_c_target} PRIVATE ninlil)
        set_target_properties(${_c_target} PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_strict_warnings(${_c_target})
        add_test(NAME self_contained_${_header}_c11 COMMAND ${_c_target})

        set(_cxx_source "${CMAKE_CURRENT_BINARY_DIR}/self_contained_${_header}_cxx17.cpp")
        file(WRITE "${_cxx_source}"
            "#include <ninlil/${_header}.h>\n"
            "int main() { return 0; }\n"
        )
        set(_cxx_target "ninlil_self_contained_${_header}_cxx17")
        add_executable(${_cxx_target} "${_cxx_source}")
        target_link_libraries(${_cxx_target} PRIVATE ninlil)
        target_compile_features(${_cxx_target} PRIVATE cxx_std_17)
        ninlil_apply_strict_warnings(${_cxx_target})
        add_test(NAME self_contained_${_header}_cxx17 COMMAND ${_cxx_target})
    endforeach()
endif()
