// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// memcpy for OpenVM (rv64im), exploiting native misaligned access.
//
// OpenVM's RV64 load/store adapters resolve an arbitrary byte offset inside
// the 8-byte memory block — and a block-crossing access — within a single
// instruction, so a misaligned `ld`/`sd` costs exactly what an aligned one
// costs. That makes the usual musl-style structure counterproductive here:
//
//   * SP1's memcpy (which this guest previously borrowed) first copies up
//     to 7 bytes to align `src`, then dispatches on `dst`'s offset into
//     shift-merge loops that reassemble each word with `ld; slli; srli; or`
//     — all of it work to dodge unaligned accesses.
//   * OpenVM's own Rust-toolchain memcpy (crates/toolchain/openvm/src/
//     memcpy.s, musl compiled by clang) has the same shape, only 4-byte
//     granular: it aligns to 4 and moves the bulk with `lw`/`sw`.
//
// Neither needs to do any of that on OpenVM. This implementation drops the
// alignment preamble and the shift-merge paths entirely: a 32-byte unrolled
// body, then a branch-free descending size dispatch (16/8/4/2/1) so short
// copies — which dominate, being hashes, MPT node fragments and pointers —
// resolve in one or two wide accesses instead of a byte loop.
//
// The size dispatch is the part that matters: an earlier attempt kept the
// wide body but left a `while (n--) *d++ = *s++;` tail, and GCC compiled
// that tail into byte loads/stores that small copies always fell into,
// costing +193M instructions on mainnet block 24001988.
//
// Compiled with -fno-builtin so the compiler does not turn this into a call
// to itself. Every __builtin_memcpy below has a constant size and lowers to
// a single load/store pair.

#include <cstddef>
#include <cstdint>

extern "C" [[gnu::used]] void* memcpy(void* dst, const void* src, size_t n)
{
    auto* d = static_cast<uint8_t*>(dst);
    const auto* s = static_cast<const uint8_t*>(src);

    // Bulk: 32 bytes per iteration, four independent dword accesses.
    while (n >= 32)
    {
        uint64_t w0, w1, w2, w3;
        __builtin_memcpy(&w0, s, 8);
        __builtin_memcpy(&w1, s + 8, 8);
        __builtin_memcpy(&w2, s + 16, 8);
        __builtin_memcpy(&w3, s + 24, 8);
        __builtin_memcpy(d, &w0, 8);
        __builtin_memcpy(d + 8, &w1, 8);
        __builtin_memcpy(d + 16, &w2, 8);
        __builtin_memcpy(d + 24, &w3, 8);
        d += 32;
        s += 32;
        n -= 32;
    }

    // Tail: at most one access per width, no loops.
    if (n & 16)
    {
        uint64_t w0, w1;
        __builtin_memcpy(&w0, s, 8);
        __builtin_memcpy(&w1, s + 8, 8);
        __builtin_memcpy(d, &w0, 8);
        __builtin_memcpy(d + 8, &w1, 8);
        d += 16;
        s += 16;
    }
    if (n & 8)
    {
        uint64_t w;
        __builtin_memcpy(&w, s, 8);
        __builtin_memcpy(d, &w, 8);
        d += 8;
        s += 8;
    }
    if (n & 4)
    {
        uint32_t w;
        __builtin_memcpy(&w, s, 4);
        __builtin_memcpy(d, &w, 4);
        d += 4;
        s += 4;
    }
    if (n & 2)
    {
        uint16_t w;
        __builtin_memcpy(&w, s, 2);
        __builtin_memcpy(d, &w, 2);
        d += 2;
        s += 2;
    }
    if (n & 1)
        *d = *s;

    return dst;
}
