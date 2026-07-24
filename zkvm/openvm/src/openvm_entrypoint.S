// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* OpenVM zkVM entry point for rv64im C++ guest.
 *
 * Memory layout (openvm-platform crate: crates/toolchain/platform/src/memory.rs,
 * branch develop-v2.1.0 — the RV64 target keeps the same addresses):
 *   STACK_TOP  = 0x0020_0400   (initial SP; stack grows downward)
 *   TEXT_START = 0x0020_0800   (code loads here)
 *   MEM_SIZE   = 0x2000_0000   (512 MiB)
 *
 * Matches the Rust entrypoint OpenVM's own toolchain crate emits
 * (crates/toolchain/openvm/src/lib.rs, the `global_asm!` block after
 * `#[no_mangle] unsafe extern "C" fn __start()`): set gp, set sp from
 * STACK_TOP, call the runtime initialiser.
 */

    .section .text._start
    .globl _start
    .type  _start, @function
_start:
    /* Initialise the global pointer for RISC-V GP-relative relaxation. */
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    /* Set stack pointer to OpenVM's STACK_TOP.
       The stack grows downward from 0x200400 toward GUEST_MIN_MEM (0x400). */
    li      sp, 0x00200400

    /* Call the C++ runtime initialiser.  Runs global constructors,
       calls main(), then halts via the `terminate` custom instruction.
       Never returns. */
    call    __start

    /* Unreachable: spin as a safety net. */
1:  j       1b

    .size _start, . - _start
