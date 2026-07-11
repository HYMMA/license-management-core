cmake_minimum_required(VERSION 3.16)
project(hymma_lm_core LANGUAGES C VERSION 0.1.0)

option(HLM_BUILD_SHARED "Build the shared library (for FFI wrappers)" ON)
option(HLM_BUILD_TESTS "Build the test suite" ON)
option(HLM_WITH_WIN_PORTS "Build Windows ports (WinHTTP, CNG, SMBIOS id)" ${WIN32})

set(CMAKE_C_STANDARD 99)
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
set(CMAKE_C_STANDARD_REQUIRED ON)

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
    PUBLIC include
    PRIVATE src/core src/crypto)
set_target_properties(hymmalm_static PROPERTIES OUTPUT_NAME hymmalm)

# Shared library — what language wrappers P/Invoke into.
if(HLM_BUILD_SHARED)
    add_library(hymmalm SHARED ${HLM_CORE_SOURCES})
    target_include_directories(hymmalm
        PUBLIC include
        PRIVATE src/core src/crypto)
    set_target_properties(hymmalm PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        C_VISIBILITY_PRESET default)
    if(WIN32)
        target_link_libraries(hymmalm PRIVATE winhttp bcrypt)
    endif()
endif()

if(WIN32)
    target_link_libraries(hymmalm_static PUBLIC winhttp bcrypt)
else()
    target_link_libraries(hymmalm_static PUBLIC ${CMAKE_DL_LIBS})
    if(TARGET hymmalm)
        target_link_libraries(hymmalm PRIVATE ${CMAKE_DL_LIBS})
    endif()
endif()

if(MSVC)
    foreach(tgt hymmalm_static hymmalm)
        if(TARGET ${tgt})
            target_compile_options(${tgt} PRIVATE /W4)
        endif()
    endforeach()
else()
    foreach(tgt hymmalm_static hymmalm)
        if(TARGET ${tgt})
            target_compile_options(${tgt} PRIVATE -Wall -Wextra)
        endif()
    endforeach()
endif()

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
endif()

if(HLM_WITH_WIN_PORTS)
    add_executable(hlm_machineid tools/machineid.c)
    target_link_libraries(hlm_machineid PRIVATE hymmalm_static)
endif()
