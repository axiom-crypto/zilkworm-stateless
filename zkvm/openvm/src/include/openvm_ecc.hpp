// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#pragma once
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint64_t

// hint_store_u64 / hint_buffer_chunked / HINT_WORD_BYTES for the
// hint-based square root below.
#include "openvm_syscalls.hpp"

// OpenVM guest ABI — modular-arithmetic / elliptic-curve custom instructions
// (RV64IM, openvm-org/openvm  branch develop-v2.1.0).
//
// All encodings verified directly against the pinned OpenVM source:
//   - extensions/algebra/guest/src/lib.rs   (OPCODE=0x2b, MODULAR_ARITHMETIC_FUNCT3,
//                                            COMPLEX_EXT_FIELD_FUNCT3, ModArithBaseFunct7,
//                                            ComplexExtFieldBaseFunct7)
//   - extensions/algebra/moduli-macros/src/lib.rs  (operand shapes, setup protocol)
//   - extensions/ecc/guest/src/lib.rs       (SW_FUNCT3, SwBaseFunct7)
//   - extensions/ecc/sw-macros/src/lib.rs   (EC operand shapes, setup protocol)
//
// Conventions (same for every instruction below):
//   * opcode custom-1 (0x2b); R-type.
//   * funct7 = index * 8 + kind, where `index` is the position of the
//     modulus / fp2 field / curve in the HOST VM config. The host-side
//     zilkworm_vm_config() in openvm-eth's bin/zilkworm-benchmark MUST list
//     moduli/fp2/curves in exactly the order of the indices defined here.
//   * Register operands hold POINTERS to little-endian fixed-width byte
//     arrays (32 bytes for 256-bit moduli). Pointers must be 8-byte aligned
//     (the RV64 memory system reads 8-byte blocks; intx::uint256 already is).
//   * Values are canonical (reduced, < N). The host normalizes op results to
//     canonical form; inputs of IsEq must be reduced (enforced via SETUP_ISEQ).
//   * Before the first arithmetic op on a modulus/fp2/curve, its SETUP
//     instructions must execute once (lazy, mirrors the Rust guest libs'
//     once_cell). The setup_* helpers below handle this.
//
// Modular ops (funct3 = 0b000): funct7 = mod_idx*8 + kind
//   kind: AddMod=0 SubMod=1 MulMod=2 DivMod=3 IsEqMod=4 SetupMod=5
//         HintNonQr=6 HintSqrt=7
//   add/sub/mul/div: rd = dst ptr, rs1 = x ptr, rs2 = y ptr  (dst = x op y)
//   is_eq: rd = result register (bool), rs1/rs2 = ptrs (inputs must be reduced)
//   setup: three insns discriminated by the NUMBER of the rs2 register:
//          x0 -> SETUP_ADDSUB, x1 -> SETUP_MULDIV, x2 -> SETUP_ISEQ;
//          rd = ptr to a writable N-byte scratch buffer (x2 variant also
//          writes the rd register), rs1 = ptr to the modulus LE bytes.
//
// Fp2 ops (funct3 = 0b010): funct7 = fp2_idx*8 + kind
//   kind: Add=0 Sub=1 Mul=2 Div=3 Setup=4
//   Operands point to (c0 || c1), 2*N bytes, canonical LE coefficients.
//   setup: two insns, rs2 register number discriminates: x0 -> ADDSUB,
//          x1 -> MULDIV; rd = writable 2*N-byte scratch, rs1 = modulus ptr.
//
// Short Weierstrass ops (funct3 = 0b001): funct7 = curve_idx*8 + kind
//   kind: SwAddNe=0 SwDouble=1 SwSetup=2
//   add_ne: rd = dst point ptr, rs1 = p ptr, rs2 = q ptr. Affine points are
//           (x || y), 2*N bytes canonical LE. REQUIRES p.x != q.x and both
//           points not identity — callers must branch (see msm helpers).
//   double: rd = dst point ptr, rs1 = p ptr, rs2 = x0.
//   setup:  two insns: rs1 = ptr to (modulus || curve_a), 2*N bytes;
//           first with rs2 = ptr to a point (x2,y2) with x2 != modulus
//           (SETUP_EC_ADD_NE), then with rs2 = x0 (SETUP_EC_DOUBLE);
//           rd = ptr to writable scratch of 2 points (4*N bytes).

namespace openvm {

// Index assignments — keep in sync with bin/zilkworm-benchmark's
// zilkworm_vm_config() in openvm-eth (order of supported_moduli /
// fp2 supported_moduli / ecc supported_curves).
// These MUST match SdkVmConfig::standard() (openvm crates/sdk-config), which
// is the config the openvm-eth benchmark hosts use, so the Zilkworm and Reth
// guests run on an identical circuit:
//   moduli:  0 = bn254 Fp,     1 = bn254 Fr,
//            2 = secp256k1 Fp, 3 = secp256k1 Fr,
//            4 = p256 Fp,      5 = p256 Fr,
//            6 = bls12-381 Fp (48-byte limbs), 7 = bls12-381 Fr
//   fp2:     0 = Bn254Fp2,     1 = Bls12_381Fp2
//   curves:  0 = bn254 G1,     1 = secp256k1, 2 = p256, 3 = bls12-381 G1
inline constexpr int MOD_BN254_FP = 0;
inline constexpr int MOD_BN254_FR = 1;
inline constexpr int MOD_SECP256K1_FP = 2;
inline constexpr int MOD_SECP256K1_FR = 3;
inline constexpr int MOD_P256_FP = 4;
inline constexpr int MOD_P256_FR = 5;
inline constexpr int MOD_BLS_FP = 6;
inline constexpr int MOD_BLS_FR = 7;
inline constexpr int FP2_BN254 = 0;
inline constexpr int FP2_BLS = 1;
inline constexpr int CURVE_BN254 = 0;
inline constexpr int CURVE_SECP256K1 = 1;
inline constexpr int CURVE_P256 = 2;
inline constexpr int CURVE_BLS_G1 = 3;

// ─────────────────────────────────────────────────────────────────────────
// Raw instruction emitters. F7EXPR must be a literal arithmetic expression
// (it is stringified into the .insn text and evaluated by the assembler).
// ─────────────────────────────────────────────────────────────────────────
#define OPENVM_INSN_R3(F3, F7EXPR, RD, RS1, RS2)                              \
    asm volatile(".insn r 0x2b, " #F3 ", (" #F7EXPR "), %0, %1, %2"           \
                 :: "r"(RD), "r"(RS1), "r"(RS2) : "memory")

#define OPENVM_INSN_R2_X0(F3, F7EXPR, RD, RS1)                                \
    asm volatile(".insn r 0x2b, " #F3 ", (" #F7EXPR "), %0, %1, x0"           \
                 :: "r"(RD), "r"(RS1) : "memory")

// Modular arithmetic (funct3 = 0). dst = x op y, 32-byte LE canonical values.
#define OPENVM_MOD_OP(MOD_IDX, KIND, DST, X, Y)                               \
    OPENVM_INSN_R3(0, (MOD_IDX)*8 + (KIND), DST, X, Y)

// Fp2 arithmetic (funct3 = 2). Operands are (c0 || c1), 64-byte buffers.
#define OPENVM_FP2_OP(FP2_IDX, KIND, DST, X, Y)                               \
    OPENVM_INSN_R3(2, (FP2_IDX)*8 + (KIND), DST, X, Y)

// Short Weierstrass (funct3 = 1). Points are (x || y), 64-byte buffers.
#define OPENVM_SW_ADD_NE(CURVE_IDX, DST, P, Q)                                \
    OPENVM_INSN_R3(1, (CURVE_IDX)*8 + 0, DST, P, Q)
#define OPENVM_SW_DOUBLE(CURVE_IDX, DST, P)                                   \
    OPENVM_INSN_R2_X0(1, (CURVE_IDX)*8 + 1, DST, P)

// ─────────────────────────────────────────────────────────────────────────
// Setup sequences. Each must run once before the first use of the
// corresponding modulus / fp2 field / curve.
// ─────────────────────────────────────────────────────────────────────────

// Modulus setup: SETUP_ADDSUB (rs2=x0), SETUP_MULDIV (rs2=x1),
// SETUP_ISEQ (rs2=x2; also writes the rd register).
#define OPENVM_MOD_SETUP(MOD_IDX, SCRATCH, MODULUS)                            \
    do {                                                                       \
        asm volatile(".insn r 0x2b, 0, ((" #MOD_IDX ")*8 + 5), %0, %1, x0"     \
                     :: "r"(SCRATCH), "r"(MODULUS) : "memory");                \
        asm volatile(".insn r 0x2b, 0, ((" #MOD_IDX ")*8 + 5), %0, %1, x1"     \
                     :: "r"(SCRATCH), "r"(MODULUS) : "memory");                \
        uintptr_t tmp_ = reinterpret_cast<uintptr_t>(SCRATCH);                 \
        asm volatile(".insn r 0x2b, 0, ((" #MOD_IDX ")*8 + 5), %0, %1, x2"     \
                     : "+r"(tmp_) : "r"(MODULUS) : "memory");                  \
    } while (0)

// Fp2 setup: ADDSUB (rs2=x0) then MULDIV (rs2=x1). SCRATCH is 2*N bytes and
// MODULUS2 points to the modulus bytes CONCATENATED TWICE (modulus||modulus,
// 2*N bytes) — one copy per coefficient, mirroring complex-macros'
// two_modulus_bytes.
#define OPENVM_FP2_SETUP(FP2_IDX, SCRATCH, MODULUS)                            \
    do {                                                                       \
        asm volatile(".insn r 0x2b, 2, ((" #FP2_IDX ")*8 + 4), %0, %1, x0"     \
                     :: "r"(SCRATCH), "r"(MODULUS) : "memory");                \
        asm volatile(".insn r 0x2b, 2, ((" #FP2_IDX ")*8 + 4), %0, %1, x1"     \
                     :: "r"(SCRATCH), "r"(MODULUS) : "memory");                \
    } while (0)

// Curve setup: SETUP_EC_ADD_NE (rs2 = ptr to (1,1) point), then
// SETUP_EC_DOUBLE (rs2 = x0). P1 = (modulus || curve_a), SCRATCH = 4*N bytes.
#define OPENVM_SW_SETUP(CURVE_IDX, SCRATCH, P1, P2)                            \
    do {                                                                       \
        asm volatile(".insn r 0x2b, 1, ((" #CURVE_IDX ")*8 + 2), %0, %1, %2"   \
                     :: "r"(SCRATCH), "r"(P1), "r"(P2) : "memory");            \
        asm volatile(".insn r 0x2b, 1, ((" #CURVE_IDX ")*8 + 2), %0, %1, x0"   \
                     :: "r"(SCRATCH), "r"(P1) : "memory");                     \
    } while (0)

// ─────────────────────────────────────────────────────────────────────────
// Modulus constants (little-endian, 32 bytes) and lazy setup guards.
// ─────────────────────────────────────────────────────────────────────────
namespace ecc_detail {

// secp256k1: p = 2^256 - 2^32 - 977
alignas(8) inline constexpr uint8_t SECP256K1_FP_LE[32] = {
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
// secp256k1: n (group order)
alignas(8) inline constexpr uint8_t SECP256K1_FR_LE[32] = {
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf,
    0xe6, 0xdc, 0xae, 0xba, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
// bn254 (alt_bn128): p
alignas(8) inline constexpr uint8_t BN254_FP_LE[32] = {
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68,
    0x91, 0x6a, 0x81, 0x97, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30};
// bn254: r (group order)
alignas(8) inline constexpr uint8_t BN254_FR_LE[32] = {
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79,
    0x48, 0xe8, 0x33, 0x28, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30};

// bls12-381: p (48 bytes little-endian)
alignas(8) inline constexpr uint8_t BLS_FP_LE[48] = {
    0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9, 0xff, 0xff, 0x53, 0xb1,
    0xfe, 0xff, 0xab, 0x1e, 0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
    0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64, 0xd7, 0xac, 0x4b, 0x43,
    0xb6, 0xa7, 0x1b, 0x4b, 0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a};
// bls12-381: r (scalar field order, 32 bytes little-endian)
alignas(8) inline constexpr uint8_t BLS_FR_LE[32] = {
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff,
    0x02, 0xa4, 0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
    0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73};
// bls12-381 modulus twice for the Fp2 setup (one copy per coefficient).
alignas(8) inline constexpr uint8_t BLS_FP2_MODULUS2[96] = {
    0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9, 0xff, 0xff, 0x53, 0xb1,
    0xfe, 0xff, 0xab, 0x1e, 0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
    0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64, 0xd7, 0xac, 0x4b, 0x43,
    0xb6, 0xa7, 0x1b, 0x4b, 0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a,
    0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9, 0xff, 0xff, 0x53, 0xb1,
    0xfe, 0xff, 0xab, 0x1e, 0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
    0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64, 0xd7, 0xac, 0x4b, 0x43,
    0xb6, 0xa7, 0x1b, 0x4b, 0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a};
// bls12-381 curve setup p1 = (p || a) with a = 0.
alignas(8) inline constexpr uint8_t BLS_CURVE_P1[96] = {
    0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9, 0xff, 0xff, 0x53, 0xb1,
    0xfe, 0xff, 0xab, 0x1e, 0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
    0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64, 0xd7, 0xac, 0x4b, 0x43,
    0xb6, 0xa7, 0x1b, 0x4b, 0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
// (x2, y2) = (1, 1) for the 96-byte-coordinate curve setups.
alignas(8) inline constexpr uint8_t SW_SETUP_P2_48[96] = {
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// bn254 modulus twice (one copy per Fp2 coefficient) for the Fp2 setup.
alignas(8) inline constexpr uint8_t BN254_FP2_MODULUS2[64] = {
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68,
    0x91, 0x6a, 0x81, 0x97, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68,
    0x91, 0x6a, 0x81, 0x97, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30};

// (modulus || a) pairs for curve setups; a = 0 for both secp256k1 and bn254.
alignas(8) inline constexpr uint8_t SECP256K1_CURVE_P1[64] = {
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // a = 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
alignas(8) inline constexpr uint8_t BN254_CURVE_P1[64] = {
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68,
    0x91, 0x6a, 0x81, 0x97, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
    // a = 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
// (x2, y2) = (1, 1): x2 != modulus, as SETUP_EC_ADD_NE requires.
alignas(8) inline constexpr uint8_t SW_SETUP_P2[64] = {
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

} // namespace ecc_detail

// Lazy one-time setups (single-threaded guest: plain statics suffice).
// The instruction sequences are noinline+cold: they execute at most once,
// and inlining them at every arithmetic wrapper call site bloats the text.
[[gnu::noinline, gnu::cold]] inline void setup_secp256k1_fp() noexcept {
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[32];
    OPENVM_MOD_SETUP(2, scratch, ecc_detail::SECP256K1_FP_LE);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_secp256k1_fr() noexcept {
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[32];
    OPENVM_MOD_SETUP(3, scratch, ecc_detail::SECP256K1_FR_LE);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_bn254_fp() noexcept {
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[32];
    OPENVM_MOD_SETUP(0, scratch, ecc_detail::BN254_FP_LE);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_bn254_fr() noexcept {
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[32];
    OPENVM_MOD_SETUP(1, scratch, ecc_detail::BN254_FR_LE);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_bn254_fp2() noexcept {
    setup_bn254_fp();
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[64];
    OPENVM_FP2_SETUP(0, scratch, ecc_detail::BN254_FP2_MODULUS2);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_secp256k1_curve() noexcept {
    setup_secp256k1_fp();
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[128];
    OPENVM_SW_SETUP(1, scratch, ecc_detail::SECP256K1_CURVE_P1, ecc_detail::SW_SETUP_P2);
    done = true;
}
[[gnu::noinline, gnu::cold]] [[gnu::noinline, gnu::cold]] inline void setup_bls_fp() noexcept {
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[48];
    OPENVM_MOD_SETUP(6, scratch, ecc_detail::BLS_FP_LE);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_bls_fr() noexcept {
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[32];
    OPENVM_MOD_SETUP(7, scratch, ecc_detail::BLS_FR_LE);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_bls_fp2() noexcept {
    setup_bls_fp();
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[96];
    OPENVM_FP2_SETUP(1, scratch, ecc_detail::BLS_FP2_MODULUS2);
    done = true;
}
[[gnu::noinline, gnu::cold]] inline void setup_bls_curve() noexcept {
    setup_bls_fp();
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[192];
    OPENVM_SW_SETUP(3, scratch, ecc_detail::BLS_CURVE_P1, ecc_detail::SW_SETUP_P2_48);
    done = true;
}

inline void setup_bn254_curve() noexcept {
    setup_bn254_fp();
    static bool done = false;
    if (done) [[likely]] return;
    alignas(8) uint8_t scratch[128];
    OPENVM_SW_SETUP(0, scratch, ecc_detail::BN254_CURVE_P1, ecc_detail::SW_SETUP_P2);
    done = true;
}

// ─────────────────────────────────────────────────────────────────────────
// Typed wrappers. All pointers reference canonical little-endian values;
// 32 bytes per field element, 64 bytes per Fp2 element / affine point.
// dst may alias x or y.
// ─────────────────────────────────────────────────────────────────────────

// secp256k1 base field (index 0)
inline void secp256k1_fp_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fp();
    OPENVM_MOD_OP(2, 0, dst, x, y);
}
inline void secp256k1_fp_submod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fp();
    OPENVM_MOD_OP(2, 1, dst, x, y);
}
inline void secp256k1_fp_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fp();
    OPENVM_MOD_OP(2, 2, dst, x, y);
}
// dst = x / y; y must be invertible (callers must guard y != 0).
inline void secp256k1_fp_divmod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fp();
    OPENVM_MOD_OP(2, 3, dst, x, y);
}

// secp256k1 scalar field (index 1)
inline void secp256k1_fr_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fr();
    OPENVM_MOD_OP(3, 0, dst, x, y);
}
inline void secp256k1_fr_submod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fr();
    OPENVM_MOD_OP(3, 1, dst, x, y);
}
inline void secp256k1_fr_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fr();
    OPENVM_MOD_OP(3, 2, dst, x, y);
}
inline void secp256k1_fr_divmod(void* dst, const void* x, const void* y) noexcept {
    setup_secp256k1_fr();
    OPENVM_MOD_OP(3, 3, dst, x, y);
}

// bn254 base field (index 2)
inline void bn254_fp_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp();
    OPENVM_MOD_OP(0, 0, dst, x, y);
}
inline void bn254_fp_submod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp();
    OPENVM_MOD_OP(0, 1, dst, x, y);
}
inline void bn254_fp_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp();
    OPENVM_MOD_OP(0, 2, dst, x, y);
}
inline void bn254_fp_divmod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp();
    OPENVM_MOD_OP(0, 3, dst, x, y);
}

// bn254 Fp2 (index 0); operands are (c0 || c1), 64 bytes.
inline void bn254_fp2_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp2();
    OPENVM_FP2_OP(0, 0, dst, x, y);
}
inline void bn254_fp2_submod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp2();
    OPENVM_FP2_OP(0, 1, dst, x, y);
}
inline void bn254_fp2_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp2();
    OPENVM_FP2_OP(0, 2, dst, x, y);
}

// ─────────────────────────────────────────────────────────────────────────
// Hint-based square root (ModArithBaseFunct7::HintSqrt = kind 7).
//
// The instruction pushes (is_square: u64, root: N bytes) onto the hint
// stream; the guest reads them back and must verify, since a hint is
// untrusted. This replaces the 253-squaring / 13-multiply addition chain
// evmone uses for secp256k1 point decompression with one hint plus one
// multiply.
//
// Returns true when the host claims `x` is a quadratic residue and writes
// the candidate root to `out`. The caller MUST check `out * out == x` (and
// that `out` is reduced). A `false` return is NOT proof that `x` is a
// non-residue — verifying that claim needs the non-QR witness — so callers
// should fall back to computing the root themselves, which stays sound.
// ─────────────────────────────────────────────────────────────────────────
inline bool secp256k1_fp_hint_sqrt(const void* x, void* out) noexcept {
    setup_secp256k1_fp();
    asm volatile(".insn r 0x2b, 0b000, (2*8 + 7), x0, %0, x0" :: "r"(x) : "memory");
    alignas(8) uint64_t is_square = 0;
    hint_store_u64(&is_square);
    hint_buffer_chunked(static_cast<uint8_t*>(out), 32 / HINT_WORD_BYTES);
    return is_square == 1;
}

inline bool bn254_fp_hint_sqrt(const void* x, void* out) noexcept {
    setup_bn254_fp();
    asm volatile(".insn r 0x2b, 0b000, (0*8 + 7), x0, %0, x0" :: "r"(x) : "memory");
    alignas(8) uint64_t is_square = 0;
    hint_store_u64(&is_square);
    hint_buffer_chunked(static_cast<uint8_t*>(out), 32 / HINT_WORD_BYTES);
    return is_square == 1;
}

// secp256k1 curve point ops (curve index 0); points (x || y), 64 bytes.
// add_ne REQUIRES p.x != q.x and neither operand the identity.
inline void secp256k1_ec_add_ne(void* dst, const void* p, const void* q) noexcept {
    setup_secp256k1_curve();
    OPENVM_SW_ADD_NE(1, dst, p, q);
}
inline void secp256k1_ec_double(void* dst, const void* p) noexcept {
    setup_secp256k1_curve();
    OPENVM_SW_DOUBLE(1, dst, p);
}

// bn254 Fp2 division (dst = x / y); y must be invertible.
inline void bn254_fp2_divmod(void* dst, const void* x, const void* y) noexcept {
    setup_bn254_fp2();
    OPENVM_FP2_OP(0, 3, dst, x, y);
}

// bls12-381 base field (index 4); 48-byte LE canonical values.
inline void bls_fp_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp();
    OPENVM_MOD_OP(6, 0, dst, x, y);
}
inline void bls_fp_submod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp();
    OPENVM_MOD_OP(6, 1, dst, x, y);
}
inline void bls_fp_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp();
    OPENVM_MOD_OP(6, 2, dst, x, y);
}
inline void bls_fp_divmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp();
    OPENVM_MOD_OP(6, 3, dst, x, y);
}

// bls12-381 scalar field (index 5); 32-byte LE canonical values.
inline void bls_fr_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fr();
    OPENVM_MOD_OP(7, 0, dst, x, y);
}
inline void bls_fr_submod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fr();
    OPENVM_MOD_OP(7, 1, dst, x, y);
}
inline void bls_fr_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fr();
    OPENVM_MOD_OP(7, 2, dst, x, y);
}

// bls12-381 Fp2 (index 1); operands are (c0 || c1), 96 bytes.
inline void bls_fp2_addmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp2();
    OPENVM_FP2_OP(1, 0, dst, x, y);
}
inline void bls_fp2_submod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp2();
    OPENVM_FP2_OP(1, 1, dst, x, y);
}
inline void bls_fp2_mulmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp2();
    OPENVM_FP2_OP(1, 2, dst, x, y);
}
inline void bls_fp2_divmod(void* dst, const void* x, const void* y) noexcept {
    setup_bls_fp2();
    OPENVM_FP2_OP(1, 3, dst, x, y);
}

// bls12-381 G1 point ops (curve index 2); points (x || y), 96 bytes.
inline void bls_ec_add_ne(void* dst, const void* p, const void* q) noexcept {
    setup_bls_curve();
    OPENVM_SW_ADD_NE(3, dst, p, q);
}
inline void bls_ec_double(void* dst, const void* p) noexcept {
    setup_bls_curve();
    OPENVM_SW_DOUBLE(3, dst, p);
}

// bn254 G1 point ops (curve index 1)
inline void bn254_ec_add_ne(void* dst, const void* p, const void* q) noexcept {
    setup_bn254_curve();
    OPENVM_SW_ADD_NE(0, dst, p, q);
}
inline void bn254_ec_double(void* dst, const void* p) noexcept {
    setup_bn254_curve();
    OPENVM_SW_DOUBLE(0, dst, p);
}

} // namespace openvm
