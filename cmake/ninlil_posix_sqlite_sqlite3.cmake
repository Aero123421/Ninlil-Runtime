# SQLite3 discovery, static vs shared detection, and static system-deps
# propagation for the POSIX SQLite storage port export.

# Directory of this module (stable inside functions; CMAKE_CURRENT_LIST_DIR
# during a call may be the caller's listfile).
set(NINLIL_POSIX_SQLITE_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}")

set(NINLIL_SQLITE_LINKAGE "AUTO" CACHE STRING
    "SQLite preference: exact closed set AUTO | STATIC | SHARED")
set_property(CACHE NINLIL_SQLITE_LINKAGE PROPERTY STRINGS AUTO STATIC SHARED)

# Closed-set validation immediately after the cache entry exists.
string(TOUPPER "${NINLIL_SQLITE_LINKAGE}" _ninlil_sqlite_linkage_norm)
if(NOT _ninlil_sqlite_linkage_norm STREQUAL "AUTO"
   AND NOT _ninlil_sqlite_linkage_norm STREQUAL "STATIC"
   AND NOT _ninlil_sqlite_linkage_norm STREQUAL "SHARED")
    message(FATAL_ERROR
        "NINLIL_SQLITE_LINKAGE must be exactly AUTO, STATIC, or SHARED "
        "(got '${NINLIL_SQLITE_LINKAGE}')")
endif()
# Normalize cache to canonical spelling so later STREQUAL checks are exact.
set(NINLIL_SQLITE_LINKAGE "${_ninlil_sqlite_linkage_norm}" CACHE STRING
    "SQLite preference: exact closed set AUTO | STATIC | SHARED" FORCE)

set(NINLIL_SQLITE_IS_STATIC FALSE)
set(NINLIL_SQLITE_LIBRARY_PATH "")
set(NINLIL_SQLITE_NEEDS_ZLIB FALSE)
set(NINLIL_SQLITE_STATIC_SYSTEM_DEPS "")
set(NINLIL_TEST_SQLITE_INTERPOSE_BACKEND "")

function(ninlil_sqlite3_resolve_library_path out_var)
    set(_loc "")
    if(TARGET SQLite3::SQLite3)
        foreach(_prop
                IMPORTED_LOCATION
                IMPORTED_LOCATION_RELEASE
                IMPORTED_LOCATION_RELWITHDEBINFO
                IMPORTED_LOCATION_MINSIZEREL
                IMPORTED_LOCATION_DEBUG
                LOCATION)
            get_target_property(_cand SQLite3::SQLite3 ${_prop})
            if(_cand AND NOT _cand STREQUAL "NOTFOUND" AND NOT _cand STREQUAL "")
                set(_loc "${_cand}")
                break()
            endif()
        endforeach()
    endif()
    if(NOT _loc AND DEFINED SQLite3_LIBRARY AND SQLite3_LIBRARY)
        set(_loc "${SQLite3_LIBRARY}")
    endif()
    set(_first "")
    if(_loc)
        list(GET _loc 0 _first)
    endif()
    set(${out_var} "${_first}" PARENT_SCOPE)
endfunction()

# Classify by reliable suffix only. Unknown/opaque paths are never guessed.
function(ninlil_sqlite3_classify_path path out_var)
    if(path STREQUAL "" OR NOT path)
        set(${out_var} "unknown" PARENT_SCOPE)
        return()
    endif()
    if(path MATCHES "\\.(a|lib)$")
        set(${out_var} "static" PARENT_SCOPE)
    elseif(path MATCHES "\\.(so|dylib|tbd|dll)(\\..*)?$")
        set(${out_var} "shared" PARENT_SCOPE)
    else()
        set(${out_var} "unknown" PARENT_SCOPE)
    endif()
endfunction()

# Explicit STATIC may accept an opaque existing file only when the operator
# forces SQLite3_LIBRARY to a real path and the file is a regular file.
# AUTO never accepts opaque paths.
function(ninlil_sqlite3_accept_opaque_static path out_var)
    set(${out_var} FALSE PARENT_SCOPE)
    if(NOT NINLIL_SQLITE_LINKAGE STREQUAL "STATIC")
        return()
    endif()
    if(NOT path OR path STREQUAL "")
        return()
    endif()
    if(NOT EXISTS "${path}")
        return()
    endif()
    if(IS_DIRECTORY "${path}")
        return()
    endif()
    # Reject obvious non-archive names that slipped past suffix checks.
    get_filename_component(_name "${path}" NAME)
    if(_name MATCHES "\\.(so|dylib|tbd|dll)(\\..*)?$")
        return()
    endif()
    set(${out_var} TRUE PARENT_SCOPE)
endfunction()

macro(ninlil_sqlite3_find_with_preference)
    set(_ninlil_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    if(NINLIL_SQLITE_LINKAGE STREQUAL "STATIC")
        if(WIN32)
            set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
        else()
            set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
        endif()
    elseif(NINLIL_SQLITE_LINKAGE STREQUAL "SHARED")
        if(APPLE)
            set(CMAKE_FIND_LIBRARY_SUFFIXES .dylib .tbd .so)
        elseif(WIN32)
            set(CMAKE_FIND_LIBRARY_SUFFIXES .dll.a .lib .dll)
        else()
            set(CMAKE_FIND_LIBRARY_SUFFIXES .so)
        endif()
    endif()
    # If the operator pre-set SQLite3_LIBRARY, honor it after classification.
    find_package(SQLite3 QUIET)
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_ninlil_saved_suffixes}")
endmacro()

function(ninlil_sqlite3_collect_static_system_deps library_path)
    set(_deps "")
    set(_needs_zlib FALSE)

    if(UNIX AND NOT APPLE)
        find_package(Threads REQUIRED)
        list(APPEND _deps Threads::Threads)
        if(CMAKE_DL_LIBS)
            list(APPEND _deps ${CMAKE_DL_LIBS})
        endif()
        list(APPEND _deps m)

        # Prefer measured link needs over nm false-positives.
        # 1) pkg-config --static may list -lz when the distro archive was
        #    built with SQLITE_HAVE_ZLIB.
        find_package(PkgConfig QUIET)
        set(_pc_wants_zlib FALSE)
        if(PkgConfig_FOUND)
            execute_process(
                COMMAND ${PKG_CONFIG_EXECUTABLE} --static --libs-only-l sqlite3
                OUTPUT_VARIABLE _pc_libs
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE _pc_rc)
            if(_pc_rc EQUAL 0 AND _pc_libs MATCHES "(^|[ \t])-lz([ \t]|$)")
                set(_pc_wants_zlib TRUE)
            endif()
        endif()

        # 2) try_compile without zlib; only if the archive truly needs compress
        #    symbols will the link fail.
        set(_probe_src "${CMAKE_BINARY_DIR}/CMakeFiles/ninlil_sqlite_static_probe.c")
        file(WRITE "${_probe_src}"
            "#include <sqlite3.h>\nint main(void){return sqlite3_libversion_number()>0?0:1;}\n")
        set(_probe_libs "${library_path};Threads::Threads")
        if(CMAKE_DL_LIBS)
            list(APPEND _probe_libs ${CMAKE_DL_LIBS})
        endif()
        list(APPEND _probe_libs m)
        try_compile(_sqlite_static_link_ok
            "${CMAKE_BINARY_DIR}/CMakeFiles/ninlil_sqlite_static_probe"
            SOURCES "${_probe_src}"
            LINK_LIBRARIES ${_probe_libs}
            OUTPUT_VARIABLE _probe_out)
        if(NOT _sqlite_static_link_ok)
            if(_probe_out MATCHES "compress|deflate|inflate|crc32| -lz")
                set(_needs_zlib TRUE)
            elseif(_pc_wants_zlib)
                set(_needs_zlib TRUE)
            else()
                message(FATAL_ERROR
                    "Static libsqlite3 failed to link with Threads/dl/m and "
                    "the failure does not look like a missing ZLIB. Output:\n"
                    "${_probe_out}")
            endif()
        elseif(_pc_wants_zlib)
            # Link succeeded without zlib even though pc lists -lz — keep lean.
            set(_needs_zlib FALSE)
        endif()

        if(_needs_zlib)
            find_package(ZLIB REQUIRED)
            list(APPEND _deps ZLIB::ZLIB)
        endif()
    elseif(APPLE)
        find_package(Threads REQUIRED)
        list(APPEND _deps Threads::Threads)
    endif()

    set(NINLIL_SQLITE_STATIC_SYSTEM_DEPS "${_deps}" PARENT_SCOPE)
    set(NINLIL_SQLITE_NEEDS_ZLIB ${_needs_zlib} PARENT_SCOPE)
endfunction()

function(ninlil_sqlite3_select_test_interpose_backend)
    set(_backend "")
    if(NOT NINLIL_BUILD_TESTS)
        set(NINLIL_TEST_SQLITE_INTERPOSE_BACKEND "" PARENT_SCOPE)
        return()
    endif()

    if(NINLIL_SQLITE_IS_STATIC)
        if(APPLE)
            message(FATAL_ERROR
                "POSIX SQLite host tests require a shared libsqlite3 on macOS "
                "(no safe static interpose backend; ld64 has no GNU --wrap). "
                "Use dynamic SQLite (NINLIL_SQLITE_LINKAGE=SHARED or AUTO with "
                "a classified dylib/tbd path) or -DNINLIL_BUILD_TESTS=OFF.")
        endif()
        if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang)$"
           AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
            set(_backend "WRAP")
        else()
            message(FATAL_ERROR
                "Static libsqlite3 host tests require Linux GNU or Clang with "
                "linker --wrap support. Compiler='${CMAKE_C_COMPILER_ID}' "
                "system='${CMAKE_SYSTEM_NAME}'. Refusing multiple-definition.")
        endif()
    else()
        set(_backend "DLSYM")
    endif()
    set(NINLIL_TEST_SQLITE_INTERPOSE_BACKEND "${_backend}" PARENT_SCOPE)
endfunction()

# Map source/binary absolute roots out of object/archive metadata (Debug too).
# GCC/Clang only; unsupported compilers fail when the port is enabled.
#
# Shipping artifact hygiene (absolute path needles = 0) is required for
# non-sanitizer production builds. Sanitizer archives are NOT ship artifacts:
# ASan global descriptors embed absolute -c paths that prefix-map cannot
# rewrite. Installed-consumer smoke skips only archive/object hygiene when
# NINLIL_ENABLE_SANITIZERS is explicitly ON (no compiler guessing). Relpath
# compile launchers (bash/Python/realpath) are intentionally not used.
function(ninlil_posix_sqlite_apply_path_remap target)
    if(NOT (CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"))
        message(FATAL_ERROR
            "POSIX SQLite storage requires GNU or Clang for "
            "-ffile-prefix-map/-fdebug-prefix-map path hygiene on installed "
            "archives (compiler='${CMAKE_C_COMPILER_ID}')")
    endif()
    include(CheckCCompilerFlag)
    # Remap this package's source/binary trees (works as top-level or add_subdirectory).
    # More-specific binary maps MUST come before the source-root maps so that
    # nested build dirs under the source tree are not partially rewritten.
    get_filename_component(_src_root "${PROJECT_SOURCE_DIR}" ABSOLUTE)
    get_filename_component(_bin_root "${CMAKE_CURRENT_BINARY_DIR}" ABSOLUTE)
    check_c_compiler_flag("-ffile-prefix-map=${_src_root}/=" NINLIL_HAVE_FFILE_PREFIX_MAP)
    check_c_compiler_flag("-fdebug-prefix-map=${_src_root}/=" NINLIL_HAVE_FDEBUG_PREFIX_MAP)
    check_c_compiler_flag("-fmacro-prefix-map=${_src_root}/=" NINLIL_HAVE_FMACRO_PREFIX_MAP)
    check_c_compiler_flag("-gno-record-gcc-switches" NINLIL_HAVE_GNO_RECORD_GCC_SWITCHES)
    # -fdebug-compilation-dir is Clang/AppleClang; GCC 13 rejects it.
    set(_have_debug_comp_dir FALSE)
    if(CMAKE_C_COMPILER_ID MATCHES "^(Clang|AppleClang)$")
        set(_have_debug_comp_dir TRUE)
    endif()
    if(NOT NINLIL_HAVE_FFILE_PREFIX_MAP OR NOT NINLIL_HAVE_FDEBUG_PREFIX_MAP)
        message(FATAL_ERROR
            "Compiler lacks -ffile-prefix-map/-fdebug-prefix-map required to "
            "keep installed POSIX SQLite archives free of absolute source/build "
            "paths (even for Debug). Upgrade GCC/Clang or disable the port.")
    endif()
    if(NOT NINLIL_HAVE_GNO_RECORD_GCC_SWITCHES)
        message(FATAL_ERROR
            "Compiler lacks -gno-record-gcc-switches; without it, Debug DWARF "
            "embeds the full -ffile-prefix-map command line (absolute roots).")
    endif()
    # GNU GCC 13 default DWARF5 .debug_line_str can retain absolute compile cwd
    # under prefix-map alone. Feature-checked -gdwarf-4 is PRIVATE for GNU only.
    # Clang/AppleClang rely on prefix-map + -fdebug-compilation-dir=.
    set(_use_dwarf4 FALSE)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        check_c_compiler_flag("-gdwarf-4" NINLIL_HAVE_GDWARF_4)
        if(NOT NINLIL_HAVE_GDWARF_4)
            message(FATAL_ERROR
                "GNU GCC path hygiene requires feature-checked -gdwarf-4; "
                "DWARF5 .debug_line_str retains absolute build cwd under "
                "prefix-map alone.")
        endif()
        set(_use_dwarf4 TRUE)
    endif()
    set(_maps
        "-ffile-prefix-map=${_bin_root}/="
        "-ffile-prefix-map=${_bin_root}="
        "-fdebug-prefix-map=${_bin_root}/="
        "-fdebug-prefix-map=${_bin_root}="
        "-ffile-prefix-map=${_src_root}/="
        "-ffile-prefix-map=${_src_root}="
        "-fdebug-prefix-map=${_src_root}/="
        "-fdebug-prefix-map=${_src_root}="
        -gno-record-gcc-switches
    )
    if(NINLIL_HAVE_FMACRO_PREFIX_MAP)
        list(APPEND _maps
            "-fmacro-prefix-map=${_bin_root}/="
            "-fmacro-prefix-map=${_bin_root}="
            "-fmacro-prefix-map=${_src_root}/="
            "-fmacro-prefix-map=${_src_root}=")
    endif()
    if(_have_debug_comp_dir)
        list(APPEND _maps "-fdebug-compilation-dir=.")
    endif()
    target_compile_options(${target} PRIVATE ${_maps})
    if(_use_dwarf4)
        # Must win over CMAKE_<LANG>_FLAGS_<CONFIG> trailing -g (DWARF5 default).
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:-gdwarf-4>
            $<$<COMPILE_LANGUAGE:CXX>:-gdwarf-4>)
        # Also append to per-config flags so generators cannot drop it.
        foreach(_cfg DEBUG RELWITHDEBINFO)
            set_property(TARGET ${target} APPEND_STRING PROPERTY
                COMPILE_FLAGS_${_cfg} " -gdwarf-4")
        endforeach()
    endif()
    if(_use_dwarf4)
        set(_hygiene_msg "GNU -gdwarf-4 + prefix-map")
    elseif(_have_debug_comp_dir)
        set(_hygiene_msg "prefix-map + -fdebug-compilation-dir=.")
    else()
        set(_hygiene_msg "prefix-map")
    endif()
    message(STATUS
        "POSIX SQLite path hygiene: ${_hygiene_msg} "
        "(compiler=${CMAKE_C_COMPILER_ID}; no Debug strip; "
        "sanitizer archives are non-ship — hygiene scan gated by "
        "NINLIL_ENABLE_SANITIZERS)")
endfunction()
