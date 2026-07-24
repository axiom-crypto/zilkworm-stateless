// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* Stateless-validator guest entry point — shared across every zkVM.
 *
 * Uses only the zkvm-standards io-interface (read_input / write_output);
 * each zkVM runtime provides the implementations over its native ABI, plus
 * an optional zkvm_io_flush() hook invoked by __start after main returns.
 *
 * Output: the canonical SSZ StatelessValidationResult (variable length) —
 *   root[32] || success[1] || offset(=37)[4] || chain_config echo
 */

#include <z6m/stateless.hpp>
#include "../common/zkvm_io.h"

#include <cstdint>

#ifdef Z6M_ECC_SELFTEST
extern "C" void z6m_ecc_selftest();
#endif

extern "C" int main()
{
#ifdef Z6M_ECC_SELFTEST
    // Validate the zkVM's ECC acceleration hooks against known vectors
    // before touching the input (halts with a failure exit on mismatch).
    z6m_ecc_selftest();
#endif
    const uint8_t* buf_ptr;
    size_t buf_size;
    read_input(&buf_ptr, &buf_size);

    const z6m::StatelessValidatorOutput result =
        z6m::run_stateless_guest(buf_ptr, buf_size);

    uint8_t pv[z6m::MAX_PUBLIC_VALUES_SIZE];
    const size_t pv_len = z6m::encode_public_values(result, pv, sizeof(pv));

    write_output(pv, pv_len);
    return 0;
}
