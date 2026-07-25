// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

#pragma once
#include <cstddef>
#include <cstdint>

// OpenVM pairing-protocol port (openvm-org/openvm@develop-v2.1.0
// guest-libs/pairing): optimal-Ate Miller loops in software over the Fp2
// custom instructions, with the final exponentiation replaced by the
// HintFinalExp residue-witness protocol (Novakovic-Eagen, eprint 2024/640
// for bn254; the gnark variant for bls12-381). Falls back to a full
// square-and-multiply final exponentiation when the host hint is dishonest,
// so results stay correct for legitimately-failing pairing checks.

namespace openvm_pairing {

// All coordinates are canonical little-endian field elements.
// bn254: P element = x||y (64 bytes), Q element = x.c0||x.c1||y.c0||y.c1
// (128 bytes). Infinity pairs must be filtered by the caller.
// Returns the boolean pairing-check result (product of pairings == 1).
bool bn254_pairing_check(const uint8_t* p_points, const uint8_t* q_points, size_t n) noexcept;

// bls12-381: P element = x||y (96 bytes), Q element = 192 bytes.
bool bls_pairing_check(const uint8_t* p_points, const uint8_t* q_points, size_t n) noexcept;

// EIP-4844 KZG proof verification over the OpenVM-accelerated bls12-381
// stack. Inputs are the EVM precompile operands: 48-byte compressed G1
// commitment/proof and 32-byte big-endian scalars z, y. Returns false on
// malformed inputs (bad encoding, off-curve, out of subgroup, unreduced
// scalars) as well as on a failing pairing check.
bool kzg_verify_proof(const uint8_t commitment[48], const uint8_t z_be[32],
    const uint8_t y_be[32], const uint8_t proof[48]) noexcept;

}  // namespace openvm_pairing
