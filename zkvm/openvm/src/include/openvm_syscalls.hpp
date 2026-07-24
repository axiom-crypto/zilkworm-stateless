// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#pragma once
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t, uint64_t

// OpenVM guest ABI — custom RISC-V instructions (RV64IM).
//
// All guest<->host communication goes through custom-0 opcode (0x0b)
// instructions, encoded here with GNU assembler's `.insn i` / `.insn r`
// directives (`riscv-none-elf-gcc`'s assembler supports these natively).
//
// Every encoding below was verified directly against the pinned OpenVM
// source (openvm-org/openvm @ branch develop-v2.1.0):
//   - extensions/riscv/guest/src/lib.rs  (SYSTEM_OPCODE, *_FUNCT3, PhantomImm,
//                                          MAX_HINT_BUFFER_DWORDS)
//   - extensions/riscv/guest/src/io.rs   (hint_store_u64!, hint_buffer_u64!,
//                                          hint_input, reveal!, print_str)
//   - crates/toolchain/platform/src/rust_rt.rs  (terminate)
//   - crates/toolchain/openvm/src/io/mod.rs     (read_vec, read_u64, reveal_u64)
//
// RV64 differences from the old rv32im ABI (v2.0.0-rc.3):
//   * the hint stream is dword (8-byte) granular: HINT_STORE moves 8 bytes,
//     HINT_BUFFER counts dwords, and read_vec's length prefix is a u64;
//   * public output is revealed as u64 words at byte offsets index*8;
//   * acceleration pointers must be 8-byte aligned (MIN_ALIGN = 8).
//
// Rust `usize`/`u64`/pointer <-> C++ `size_t`/`uint64_t`/pointer, same
// convention as sp1_syscalls.hpp / zisk_syscalls.hpp (lp64: size_t is 64-bit).

namespace openvm {

// Rust: #[repr(u16)] enum PhantomImm { HintInput = 0, PrintStr = 1, HintRandom = 2 }
static constexpr uint16_t PHANTOM_IMM_HINT_INPUT = 0;
static constexpr uint16_t PHANTOM_IMM_PRINT_STR  = 1;

// Bytes moved per hint-stream word (Rust: HINT_WORD_BYTES).
static constexpr size_t HINT_WORD_BYTES = 8;

// Maximum dwords per hint_buffer_u64 instruction (AIR constraint:
// rem_dwords < 2^MAX_HINT_BUFFER_DWORDS_BITS with BITS = 10); larger
// reads must be split into multiple chunked calls.
static constexpr size_t MAX_HINT_BUFFER_DWORDS = 1023;

// Minimum pointer alignment required by the acceleration circuits
// (Rust guest bindings copy through aligned scratch when violated).
static constexpr size_t ACCEL_MIN_ALIGN = 8;

// Rust: #[repr(C)] struct ReadVecResult — same shape as sp1/zisk's, so the
// zkVM-agnostic core (core/src/stateless.cpp) needs no changes.
struct ReadVecResult {
    uint8_t *ptr;
    size_t len;
    size_t capacity;
};

// ─────────────────────────────────────────────────────────────────────────
// Raw instruction wrappers
// ─────────────────────────────────────────────────────────────────────────

// Reset the hint stream to the next input stream.
// I-type: opcode=0x0b, funct3=0b011 (PHANTOM), rd=x0, rs1=x0, imm=HintInput(0)
[[gnu::always_inline]] inline void hint_input() noexcept {
    asm volatile(".insn i 0x0b, 0b011, x0, x0, 0" ::: "memory");
}

// Store the next 8 bytes from the hint stream to the dword at `ptr`
// (must be 8-byte aligned).
// I-type: opcode=0x0b, funct3=0b001 (HINT), rd=ptr, rs1=x0, imm=0
[[gnu::always_inline]] inline void hint_store_u64(void *ptr) noexcept {
    asm volatile(".insn i 0x0b, 0b001, %0, x0, 0" :: "r"(ptr) : "memory");
}

// Store the next 8*len bytes from the hint stream to the buffer at `ptr`.
// `len` (dword count) must be <= MAX_HINT_BUFFER_DWORDS; see hint_buffer_chunked.
// I-type: opcode=0x0b, funct3=0b001 (HINT), rd=ptr, rs1=len, imm=1
[[gnu::always_inline]] inline void hint_buffer_u64(void *ptr, size_t len) noexcept {
    asm volatile(".insn i 0x0b, 0b001, %0, %1, 1" :: "r"(ptr), "r"(len) : "memory");
}

// Read hint buffer with automatic chunking for reads larger than
// MAX_HINT_BUFFER_DWORDS (matches openvm_riscv_guest::hint_buffer_chunked).
inline void hint_buffer_chunked(uint8_t *ptr, size_t num_dwords) noexcept {
    while (num_dwords > 0) {
        size_t chunk = num_dwords < MAX_HINT_BUFFER_DWORDS ? num_dwords : MAX_HINT_BUFFER_DWORDS;
        hint_buffer_u64(ptr, chunk);
        ptr += chunk * HINT_WORD_BYTES;
        num_dwords -= chunk;
    }
}

// Read the next 8 bytes from the hint stream into a u64 register value.
// Matches openvm::io::read_u64(): hint_store_u64 into a scratch dword, then load it.
[[gnu::always_inline]] inline uint64_t hint_read_u64(void *scratch_dword) noexcept {
    hint_store_u64(scratch_dword);
    uint64_t result;
    asm volatile("ld %0, 0(%1)" : "=r"(result) : "r"(scratch_dword));
    return result;
}

// Publish `value` as the `index`-th u64 word of the public output
// (byte offset = index*8). Matches openvm::io::reveal_u64.
// I-type: opcode=0x0b, funct3=0b010 (REVEAL), rd=byte_index, rs1=value, imm=0
[[gnu::always_inline]] inline void reveal_u64(uint64_t value, size_t index) noexcept {
    uint64_t byte_index = static_cast<uint64_t>(index) * 8;
    asm volatile(".insn i 0x0b, 0b010, %0, %1, 0" :: "r"(byte_index), "r"(value) : "memory");
}

// Print a UTF-8 string to host stdout for debugging (no-op on a compliant
// prover; useful under the emulator/executor). Matches
// openvm_riscv_guest::raw_print_str_from_bytes.
// I-type: opcode=0x0b, funct3=0b011 (PHANTOM), rd=ptr, rs1=len, imm=PrintStr(1)
[[gnu::always_inline]] inline void print_str(const char *msg, size_t len) noexcept {
    asm volatile(".insn i 0x0b, 0b011, %0, %1, 1" :: "r"(msg), "r"(len) : "memory");
}

// Halt with exit code 0 (success). Matches openvm_platform::rust_rt::terminate::<0>().
// The immediate must be a compile-time constant (encoded in the instruction
// word), so — like OpenVM's own Rust runtime, which only exposes exit()/
// panic() and not a general runtime-parameterized halt — only two fixed exit
// codes are provided.
// I-type: opcode=0x0b, funct3=0 (TERMINATE), rd=x0, rs1=x0, imm=exit_code
[[gnu::always_inline, noreturn]] inline void terminate_success() noexcept {
    asm volatile(".insn i 0x0b, 0, x0, x0, 0");
    __builtin_unreachable();
}

// Halt with exit code 1 (failure). Matches
// openvm_platform::rust_rt::terminate::<1>() / openvm::process::panic().
[[gnu::always_inline, noreturn]] inline void terminate_failure() noexcept {
    asm volatile(".insn i 0x0b, 0, x0, x0, 1");
    __builtin_unreachable();
}

// ─────────────────────────────────────────────────────────────────────────
// Acceleration precompiles — R-type custom-0 instructions.
//
// Encodings verified against the pinned OpenVM source
// (openvm-org/openvm @ branch develop-v2.1.0):
//   - extensions/keccak256/guest/src/lib.rs  (KECCAKF_FUNCT3/FUNCT7, native_keccakf)
//   - extensions/sha2/guest/src/lib.rs       (SHA2_FUNCT3, Sha2BaseFunct7::Sha256)
// Both instructions carry their real data flow through memory (the operand
// registers just hold pointers), so every wrapper here takes a "memory"
// clobber and plain register operands — no register is treated as a value
// result by the compiler.
//
// The RV64 circuits require every pointer operand to be 8-byte aligned
// (MIN_ALIGN = 8 in the Rust guest bindings, which bounce through aligned
// scratch buffers otherwise). Wrappers below mirror that behaviour where
// the caller's natural buffer alignment cannot be guaranteed.
// ─────────────────────────────────────────────────────────────────────────

// Keccak-f[1600] permutation, applied in place to a 200-byte buffer (25
// little-endian uint64_t lanes — the same in-memory layout evmone's
// `uint64_t state[25]` already uses, so no repacking is needed; alignof
// (uint64_t[25]) == 8 satisfies the circuit's alignment requirement).
// R-type: opcode=0x0b, funct3=0b100, funct7=0.
// rd is the InOut buffer-pointer register per native_keccakf's ABI (the
// pointer value itself is unchanged; "+r" just matches the macro-generated
// register class OpenVM's own Rust binding uses).
[[gnu::always_inline]] inline void keccakf1600(uint64_t state[25]) noexcept {
    void *buffer = state;
    asm volatile(".insn r 0x0b, 0b100, 0, %0, x0, x0" : "+r"(buffer) :: "memory");
}

// SHA-256 compression function, single-shot over one 64-byte message block
// (unlike SP1, there is no separate message-schedule "extend" step — the
// circuit performs the full 64-round compression, including schedule
// expansion, from the raw block in one instruction).
// R-type: opcode=0x0b, funct3=0b100, funct7=2 (Sha2BaseFunct7::Sha256).
// `prev_state`/`output` are 8 little-endian uint32_t words (32 bytes) —
// matches evmone's native-order `uint32_t h[8]` exactly, no byte-swapping
// needed. `input` is the raw 64-byte block, same byte order evmone's
// `chunk` buffer already holds it in.
//
// The RV64 circuit requires 8-byte-aligned pointers; evmone's uint32_t[8]
// state and byte-granular input are only guaranteed 4-/1-byte aligned, so
// this wrapper copies through alignas(8) scratch buffers when needed
// (mirroring openvm_sha2_guest::zkvm_sha256_impl).
[[gnu::always_inline]] inline void sha256_compress_raw(
    const uint32_t prev_state[8], const uint8_t input[64], uint32_t output[8]) noexcept {
    asm volatile(".insn r 0x0b, 0b100, 2, %0, %1, %2"
                 :: "r"(output), "r"(prev_state), "r"(input) : "memory");
}

inline void sha256_compress(
    const uint32_t prev_state[8], const uint8_t input[64], uint32_t output[8]) noexcept {
    const bool state_aligned  = (reinterpret_cast<uintptr_t>(prev_state) % ACCEL_MIN_ALIGN) == 0;
    const bool input_aligned  = (reinterpret_cast<uintptr_t>(input) % ACCEL_MIN_ALIGN) == 0;
    const bool output_aligned = (reinterpret_cast<uintptr_t>(output) % ACCEL_MIN_ALIGN) == 0;
    if (state_aligned && input_aligned && output_aligned) [[likely]] {
        sha256_compress_raw(prev_state, input, output);
        return;
    }
    alignas(8) uint32_t state_buf[8];
    alignas(8) uint8_t  input_buf[64];
    alignas(8) uint32_t output_buf[8];
    const uint32_t *state_ptr = prev_state;
    const uint8_t  *input_ptr = input;
    uint32_t       *output_ptr = output;
    if (!state_aligned) {
        __builtin_memcpy(state_buf, prev_state, sizeof(state_buf));
        state_ptr = state_buf;
    }
    if (!input_aligned) {
        __builtin_memcpy(input_buf, input, sizeof(input_buf));
        input_ptr = input_buf;
    }
    if (!output_aligned)
        output_ptr = output_buf;
    sha256_compress_raw(state_ptr, input_ptr, output_ptr);
    if (!output_aligned)
        __builtin_memcpy(output, output_buf, sizeof(output_buf));
}

} // namespace openvm

// Read one length-prefixed input vector from the current hint stream.
// Mirrors sp1_syscalls.hpp's / zisk_syscalls.hpp's read_vec_raw() shape so
// core/src/stateless.cpp needs no zkVM-specific changes.
extern "C" openvm::ReadVecResult read_vec_raw() noexcept;

// Commit exit — used by main.cpp after publishing output words.
[[noreturn]] inline void syscall_halt() noexcept {
    openvm::terminate_success();
}
