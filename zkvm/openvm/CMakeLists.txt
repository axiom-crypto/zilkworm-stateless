# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

cmake_minimum_required(VERSION 3.28)

# Fetch zilkworm (same tag as SP1/ZisK builds)
# CMP0169 is unknown on CMake < 3.30; guard so the policy is only set when available.
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

include(FetchContent)

FetchContent_Declare(
    zilkworm
    GIT_REPOSITORY https://github.com/developeruche/zilkworm.git
    GIT_TAG        c3ebf73a8b9ba1957ee473d19c51cb6041c88f53 # feat/canonical-witness
    # No GIT_SHALLOW: the pin is a commit on feat/canonical-witness, not on the
    # default branch (master), so a shallow clone can't reach it — full clone.
    # OpenVM ECC/modular acceleration hooks (patches/*.patch) are applied on
    # top of the pin; the script is idempotent across reconfigures.
    PATCH_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/patches/apply-patches.sh <SOURCE_DIR>
)

FetchContent_GetProperties(zilkworm)
if(NOT zilkworm_POPULATED)
    FetchContent_Populate(zilkworm)
endif()

# Bootstrap Cable
include(${zilkworm_SOURCE_DIR}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

# Project (rv64im bare-metal for OpenVM)
project(z6m_guest_openvm C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SILKWORM_MAIN_DIR "${zilkworm_SOURCE_DIR}")

# Phase B: tell the whole build (zilkworm + core + our binary) that we are
# targeting OpenVM, enabling evmone's `#elif defined(OPENVM)` acceleration
# guards for keccak256 (keccak.c) and SHA-256 (sha256.cpp).
add_compile_definitions(OPENVM)
# Single-threaded bare-metal guest: the thread pointer is never
# initialised, so `thread_local` (e.g. rlp_sw.hpp's scratch buffer)
# reads a wild tp and corrupts control flow the first time the MPT
# encode path runs. Force the plain-static fallback.
add_compile_definitions(NO_THREAD_LOCAL)

# Build info
include(CableBuildInfo)
cable_add_buildinfo_library(
    PROJECT_NAME z6m_guest_openvm
    GIT_DESCRIBE ""
    GIT_BRANCH   ""
)

include(GNUInstallDirs)

# Global include path for openvm_syscalls.hpp (used by evmone and zilk_core
# translation units once Phase B adds `#ifdef OPENVM` guards).
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src/include")

# zilkworm third-party dependencies
set(_ZW_BIN "${CMAKE_BINARY_DIR}/zilkworm")
add_subdirectory("${zilkworm_SOURCE_DIR}/third_party" "${_ZW_BIN}/third_party")
add_subdirectory("${zilkworm_SOURCE_DIR}/zilk_core"   "${_ZW_BIN}/zilk_core")

# z6m core library
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../../core"
    "${CMAKE_BINARY_DIR}/z6m_core"
)

# OpenVM guest binary
set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/linker/openvm.xn")

# Optional in-guest ECC self-test: validates the OpenVM ECC acceleration
# hooks (bn254 add/mul/pairing) against known vectors before running block
# validation. Debug/bring-up tool — leave OFF for benchmark ELFs.
option(Z6M_ECC_SELFTEST "Run the in-guest ECC self-test before block validation" OFF)

add_executable(z6m_guest
    src/openvm_entrypoint.S
    src/openvm_runtime.cpp
    src/openvm_pairing.cpp
    ../common/main.cpp
    ../common/zkvm_accelerators.cpp
    src/atomic_stubs.c
    src/memcpy.cpp
    src/memmove.cpp
)

if(Z6M_ECC_SELFTEST)
    target_sources(z6m_guest PRIVATE ../common/zkvm_ecc_selftest.cpp)
    target_compile_definitions(z6m_guest PRIVATE Z6M_ECC_SELFTEST)
endif()

target_include_directories(z6m_guest PRIVATE
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib"
    "${zilkworm_SOURCE_DIR}/third_party/evmone/lib/evmone_precompiles"
)

# Bare-metal linker options (rv64im)
target_link_options(z6m_guest PRIVATE
    -nostdlib
    -nostartfiles
    -T${LINKER_SCRIPT}
    -z norelro
    -Wl,--gc-sections
    -Wl,-e,_start
)

# Locate the rv64im/lp64 sysroot and libgcc
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-sysroot
    OUTPUT_VARIABLE _SYSROOT OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-multi-directory
    OUTPUT_VARIABLE _MULTIDIR OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-libgcc-file-name
    OUTPUT_VARIABLE _LIBGCC_FILE OUTPUT_STRIP_TRAILING_WHITESPACE
)
get_filename_component(_LIBGCC_DIR "${_LIBGCC_FILE}" DIRECTORY)
target_link_directories(z6m_guest PRIVATE
    "${_SYSROOT}/lib/${_MULTIDIR}"
    "${_LIBGCC_DIR}"
)

target_link_libraries(z6m_guest PRIVATE
    z6m_core
    silkworm_dev
    silkworm_core
    evmone
    stdc++ c m gcc nosys
)

target_compile_options(z6m_guest PRIVATE
    -fno-asynchronous-unwind-tables
    $<$<COMPILE_LANGUAGE:CXX>:
        -fno-exceptions
        -fno-rtti
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-class-memaccess
        -Wno-ignored-attributes
        -Wno-psabi
        -Wno-narrowing
        -Wno-attributes
        -Wno-register
        -Wno-unused-function
        -Wno-cpp
        -Wno-int-in-bool-context
    >
)

set_target_properties(z6m_guest PROPERTIES
    SUFFIX                   ".elf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Post-build: flat binary images
set(OBJCOPY "${CMAKE_OBJCOPY}")
if(NOT OBJCOPY)
    find_program(OBJCOPY
        NAMES riscv-none-elf-objcopy riscv64-elf-objcopy
        REQUIRED
    )
endif()

add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${OBJCOPY} -O binary
        "$<TARGET_FILE:z6m_guest>"
        "${CMAKE_BINARY_DIR}/z6m_guest.bin"
    COMMAND ${OBJCOPY} -O binary -j .text
        "$<TARGET_FILE:z6m_guest>"
        "${CMAKE_BINARY_DIR}/z6m_guest.text"
    COMMENT "Generating flat binary images from z6m_guest.elf (OpenVM rv64im)"
)
