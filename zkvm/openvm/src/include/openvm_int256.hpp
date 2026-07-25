// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#pragma once
#include <cstdint>

// OpenVM Int256 guest ABI — 256-bit integer custom instructions.
//
// Encodings verified against openvm-org/openvm@develop-v2.1.0
// extensions/bigint/guest/src/{lib.rs,externs.rs}:
//   opcode = custom-0 (0x0b), funct3 = 0b101 (INT256_FUNCT3)
//   funct7 = Int256Funct7: Add=0 Sub=1 Xor=2 Or=3 And=4 Sll=5 Srl=6 Sra=7
//                          Slt=8 Sltu=9 Mul=10
//   rd / rs1 / rs2 are pointers to 32-byte little-endian values; the guest
//   lib documents 4-byte minimum alignment (intx::uint256 is 8-byte aligned).
//
// This is what makes evmone's `intx::uint256` EVM stack arithmetic cost one
// instruction instead of 4-limb carry chains (add/sub) or ~16 mul/mulhu
// (multiply) — the same acceleration the Rust reth guest gets through revm's
// U256. The hooks live in the intx patch (patches/intx-openvm-int256.patch).

namespace openvm_int256 {

#define OPENVM_INT256_OP(FUNCT7, DST, X, Y)                                   \
    asm volatile(".insn r 0x0b, 0b101, " #FUNCT7 ", %0, %1, %2"               \
                 :: "r"(DST), "r"(X), "r"(Y) : "memory")

// dst = x op y over 32-byte little-endian operands. dst may alias x or y.
[[gnu::always_inline]] inline void add(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(0, d, x, y);
}
[[gnu::always_inline]] inline void sub(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(1, d, x, y);
}
[[gnu::always_inline]] inline void bit_xor(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(2, d, x, y);
}
[[gnu::always_inline]] inline void bit_or(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(3, d, x, y);
}
[[gnu::always_inline]] inline void bit_and(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(4, d, x, y);
}
// Shift amount is itself a 256-bit operand (matching the Rust bindings).
[[gnu::always_inline]] inline void shl(void* d, const void* x, const void* shift) noexcept {
    OPENVM_INT256_OP(5, d, x, shift);
}
[[gnu::always_inline]] inline void shr(void* d, const void* x, const void* shift) noexcept {
    OPENVM_INT256_OP(6, d, x, shift);
}
[[gnu::always_inline]] inline void mul(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(10, d, x, y);
}
// Unsigned less-than: writes a 32-byte result whose first byte is the
// boolean (zkvm_u256_cmp_impl reads `cmp_result[0]`).
[[gnu::always_inline]] inline void sltu(void* d, const void* x, const void* y) noexcept {
    OPENVM_INT256_OP(9, d, x, y);
}

}  // namespace openvm_int256
