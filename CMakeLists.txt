cmake_minimum_required(VERSION 3.16)
project(hymma_lm_core LANGUAGES C VERSION 0.1.0)

option(HLM_BUILD_SHARED "Build the shared library (for FFI wrappers)" ON)
option(HLM_BUILD_TESTS "Build the test suite" ON)
option(HLM_WITH_WIN_PORTS "Build Windows ports (WinHTTP, CNG, SMBIOS id)" ${WIN32})

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(HLM_WERROR "Treat compiler warnings as errors (used by CI)" OFF)

set(HLM_CORE_SOURCES
    src/core/hlm_sha256.c
    src/core/hlm_sha512.c
    src/core/hlm_b64url.c
    src/core/hlm_json.c
    src/core/hlm_bignum.c
    src/core/hlm_jws.c
    src/core/hlm_license.c
    src/core/hlm_client.c
    src/core/hlm_ffi.c
    src/crypto/hlm_rsa.c
    src/crypto/hlm_p256.c
    src/crypto/hlm_ed25519.c
    src/crypto/hlm_crypto_portable.c
    src/ports/hlm_ports_common.c
)

if(HLM_WITH_WIN_PORTS)
    list(APPEND HLM_CORE_SOURCES
        src/crypto/hlm_crypto_cng.c
        src/ports/hlm_port_win.c
    )
endif()

if(NOT WIN32)
    # POSIX ports: libcurl transport (dlopen'd — no link dependency),
    # /etc/machine-id fingerprint, nanosleep, SNTP trusted time.
    list(APPEND HLM_CORE_SOURCES src/ports/hlm_port_posix.c)
endif()

# Static library — the embedded / vendoring target.
add_library(hymmalm_static STATIC ${HLM_CORE_SOURCES})
target_include_directories(hymmalm_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE src/core src/crypto)
# On Windows "hymmalm.lib" would collide with the shared target's import
# library (one silently overwrites the other in the build tree).
if(WIN32)
    set_target_properties(hymmalm_static PROPERTIES OUTPUT_NAME hymmalm_static)
else()
    set_target_properties(hymmalm_static PROPERTIES OUTPUT_NAME hymmalm)
endif()

# Shared library — what language wrappers P/Invoke into. Only the
# HLM_API-annotated hlm_ffi_* surface is exported: internal helpers
# (hlm_bn_*, hlm_sha256_*, JSON, ...) are NOT public ABI.
if(HLM_BUILD_SHARED)
    add_library(hymmalm SHARED ${HLM_CORE_SOURCES})
    target_include_directories(hymmalm
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE src/core src/crypto)
    set_target_properties(hymmalm PROPERTIES
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
    target_compile_definitions(hymmalm PRIVATE HLM_FFI_BUILD_DLL)
    if(WIN32)
        target_link_libraries(hymmalm PRIVATE winhttp bcrypt)
    endif()
endif()

if(WIN32)
    target_link_libraries(hymmalm_static PUBLIC winhttp bcrypt)
else()
    # dlopen for libcurl; pthread_once guards its one-time bring-up.
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(hymmalm_static PUBLIC ${CMAKE_DL_LIBS} Threads::Threads)
    if(TARGET hymmalm)
        target_link_libraries(hymmalm PRIVATE ${CMAKE_DL_LIBS} Threads::Threads)
    endif()
endif()

foreach(tgt hymmalm_static hymmalm)
    if(TARGET ${tgt})
        if(MSVC)
            target_compile_options(${tgt} PRIVATE /W4)
            target_compile_definitions(${tgt} PRIVATE _CRT_SECURE_NO_WARNINGS)
            if(HLM_WERROR)
                target_compile_options(${tgt} PRIVATE /WX)
            endif()
        else()
            target_compile_options(${tgt} PRIVATE -Wall -Wextra)
            if(HLM_WERROR)
                target_compile_options(${tgt} PRIVATE -Werror)
            endif()
        endif()
    endif()
endforeach()

if(HLM_BUILD_TESTS)
    enable_testing()
    add_executable(hlm_tests tests/hlm_tests.c)
    target_link_libraries(hlm_tests PRIVATE hymmalm_static)
    target_include_directories(hlm_tests PRIVATE src/core src/crypto include)
    add_test(NAME hlm_tests
             COMMAND hlm_tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/vectors.json
                               ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/vectors-eddsa.json)

    add_executable(hlm_flow_tests tests/hlm_flow_tests.c)
    target_link_libraries(hlm_flow_tests PRIVATE hymmalm_static)
    target_include_directories(hlm_flow_tests PRIVATE src/core src/crypto include)
    add_test(NAME hlm_flow_tests
             COMMAND hlm_flow_tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/vectors.json)

    if(MSVC)
        target_compile_definitions(hlm_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
        target_compile_definitions(hlm_flow_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
endif()

if(HLM_WITH_WIN_PORTS)
    add_executable(hlm_machineid tools/machineid.c)
    target_link_libraries(hlm_machineid PRIVATE hymmalm_static)
    if(MSVC)
        target_compile_definitions(hlm_machineid PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
endif()

# ------------------------------------------------------------------
# Install / export: consumers can find_package(hymmalm) instead of
# hand-copying artifacts.
# ------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS hymmalm_static EXPORT hymmalmTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
if(TARGET hymmalm)
    install(TARGETS hymmalm EXPORT hymmalmTargets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
install(DIRECTORY include/hymma DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT hymmalmTargets NAMESPACE hymma::
        FILE hymmalmTargets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/hymmalm)
configure_file(cmake/hymmalmConfig.cmake.in
               ${CMAKE_CURRENT_BINARY_DIR}/hymmalmConfig.cmake @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/hymmalmConfig.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/hymmalm)
