# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Cross-compilation toolchain for OpenVM zkVM guest (rv64im bare-metal).
#
# OpenVM branch develop-v2.1.0 executes RV64IM guests natively (the rvr
# riscv64 extension); the guest is single-threaded, so no hardware 'A'
# extension is required. Uses the same xPack riscv-none-elf-gcc toolchain
# as the SP1/ZisK builds.
#
# One-time global install (no project files required):
#   npm install --location=global xpm@latest
#   xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global
#
# CMake will auto-detect the toolchain from:
#   macOS : ~/Library/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/
#   Linux : ~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

# Toolchain auto-detection (same as SP1/ZisK)
file(GLOB _XPACK_HINTS
    "$ENV{HOME}/Library/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/.content/bin"
    "$ENV{HOME}/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/.content/bin"
)

find_program(_RISCV_GCC
    NAMES riscv-none-elf-gcc
    HINTS ${_XPACK_HINTS}
)

if(NOT _RISCV_GCC)
    message(FATAL_ERROR
        "Could not find riscv-none-elf-gcc.\n"
        "Install it globally with xpm (no project files required):\n"
        "  npm install --location=global xpm@latest\n"
        "  xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global\n"
    )
endif()

get_filename_component(_RISCV_BIN "${_RISCV_GCC}" DIRECTORY)
message(STATUS "RISC-V toolchain (rv64im): ${_RISCV_BIN}/riscv-none-elf-*")

set(CMAKE_C_COMPILER   "${_RISCV_BIN}/riscv-none-elf-gcc")
set(CMAKE_CXX_COMPILER "${_RISCV_BIN}/riscv-none-elf-g++")
set(CMAKE_ASM_COMPILER "${_RISCV_BIN}/riscv-none-elf-gcc")
set(CMAKE_AR           "${_RISCV_BIN}/riscv-none-elf-ar")
set(CMAKE_RANLIB       "${_RISCV_BIN}/riscv-none-elf-ranlib")
set(CMAKE_OBJCOPY      "${_RISCV_BIN}/riscv-none-elf-objcopy")

set(BUILD_SHARED_LIBS OFF)

# rv64im: 64-bit RISC-V with integer multiply/divide (no floating-point, no
# hardware atomics — the guest is single-threaded, atomics are stubbed).
# -mno-strict-align + -mtune=generic-ooo: OpenVM's RV64 load/store adapters
# resolve an arbitrary byte offset within the 8-byte memory block (and a
# block-crossing access) inside a single instruction, so misaligned accesses
# are supported natively.
#
# Both flags are required. -mno-strict-align only grants permission; GCC's
# RISC-V cost model still treats unaligned access as slow and keeps emitting
# byte loads/stores plus shift-merge (even through packed/may_alias types).
# Only a tune whose slow_unaligned_access is false (generic-ooo, thead-c906;
# NOT rocket or sifive-7-series) makes GCC emit a single ld/sd.
#
# Measured on mainnet block 24001988 (guest instructions / segments, where
# segments proxy proving time):
#   -mstrict-align:                 854,294,530 / 119
#   -mno-strict-align alone:        846,601,954 / 118   (permission only)
#   + -mtune=generic-ooo + memcpy:  603,344,555 /  94   (-29% / -21%)
# Reproducible builds: strip absolute paths from __FILE__/debug info.
set(_common_flags "-march=rv64im -mabi=lp64 -mno-strict-align -mtune=generic-ooo -ffunction-sections -fdata-sections -fno-PIC -ffile-prefix-map=${CMAKE_SOURCE_DIR}=. -ffile-prefix-map=${CMAKE_BINARY_DIR}=build")
# Measured on mainnet block 24001988: adding -flto=auto cost
# +15M instructions and +1 segment (586,804,615/62 -> 602,045,419/63),
# so LTO stays off.
set(_opt_flags    "-O3 -DNDEBUG -fno-stack-protector -fno-builtin-trap")
set(_no_cxx       "-fno-exceptions -fno-rtti -fno-threadsafe-statics")

set(CMAKE_C_FLAGS   "${_common_flags} ${_opt_flags}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${_common_flags} ${_opt_flags} ${_no_cxx}" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "${_common_flags}" CACHE STRING "" FORCE)

# Suppress CMake's default Release flags
set(CMAKE_C_FLAGS_RELEASE   "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)

# Disable features incompatible with bare-metal
set(BUILD_TESTING              OFF CACHE BOOL "" FORCE)
set(SILKWORM_WASM_API          OFF CACHE BOOL "" FORCE)
set(CATCH_BUILD_TESTING        OFF CACHE BOOL "" FORCE)
set(SILKWORM_CORE_USE_ABSEIL   OFF CACHE BOOL "" FORCE)

# Use static-library test mode so CMake's compiler checks pass on bare-metal
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
