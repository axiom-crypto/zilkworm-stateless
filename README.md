# zilkworm-stateless

A bare-metal C++ **stateless Ethereum block validator**, compiled to a
RISC-V guest program for zero-knowledge EVM proving. One shared execution
core is built into three zkVM guest ELFs, **SP1**, **ZisK**, and
**OpenVM**, a single implementation can be proven on any of them.

## Supported zkVMs

| zkVM | Target | SDK version (`ZKVM_VERSIONS`) |
|---|---|---|
| SP1 | `rv64im` / lp64 | `6.3.1` |
| ZisK | `rv64ima` / lp64 | `1.0.0-alpha` |
| OpenVM | `rv64im` / lp64 | `develop-v2.1.0` |

## Prerequisites

- **CMake ≥ 3.28**
- **Rust** (stable) + `cargo` — for the int-test prover hosts and the
  conformance vector generator.
- **RISC-V toolchain** — xPack `riscv-none-elf-gcc` (bundles a newlib
  sysroot; its multilib covers all three march targets):

  ```bash
  npm install --location=global xpm@latest
  xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global
  ```

  CMake auto-detects it from `~/Library/xPacks/` (macOS) or `~/.local/xPacks/`
  (Linux) — no `PATH` export needed.

Native-only flows (`make test`, `make conformance`) need just CMake + a host
C++23 compiler; the RISC-V toolchain is required only to build guest ELFs.


### Build guest programs for all supported zkVMs

```bash
make                 # builds all three: sp1, zisk, openvm
# or individually:
make guest_sp1
make guest_zisk
make guest_openvm
```

Each produces, under `build/<zkvm>/`:

```
z6m_guest.elf    ← the RISC-V ELF the prover loads
z6m_guest.bin    ← flat binary (code + data)
z6m_guest.text   ← code section only
```

### Run EF tests

Two complementary suites (both are "EF tests"; they exercise different
corpora):

**1. EF BlockchainTests, natively** (fast; exercises the shared execution
core that every zkVM guest links, so a pass here holds for all three):

```bash
make test                                   # full BlockchainTests suite
make test-only SUITE=GeneralStateTests/stExample   # one sub-directory
```

**2. EEST stateless conformance** (`tests-zkevm` fixtures — the canonical
rubric suite). First extract input/expected byte pairs from a release, then
run them through the guest core natively:

```bash
# one-time: download + unpack fixtures_zkevm.tar.gz from a tests-zkevm release,
# then extract byte pairs (inputs used verbatim — no host manipulation):
cd conformance && cargo run --release -- eest --fixtures <fixtures-dir> --out-dir pairs/ && cd ..

make conformance PAIRS=$PWD/conformance/pairs
```

### Run EF tests on a specific zkVM guest program

The suites above run the shared core on the host. To run a fixture through an
actual **zkVM guest ELF** (in that zkVM's executor), use the per-zkVM
harness. Pick any of `sp1` / `zisk` / `openvm`:

```bash
cd int-tests/sp1                    # or zisk / openvm

make mock-input                     # generate a sample input.bin (via conformance/)
make execute INPUT=mock_input.bin   # run the guest ELF in the SP1 executor,
                                    # print public values + cycle count
```

`make execute` builds the guest ELF and the prover host, runs the ELF on the
input inside the executor, and prints the committed public values (no proof).
Feed it any EEST `*.input.bin` from `conformance/pairs/` to check that a real
fixture produces the expected output in that zkVM.

### Prove and verify on a zkVM

```bash
cd int-tests/sp1                    # or zisk / openvm

make prove  INPUT=mock_input.bin OUTPUT=proof.bin   # generate + locally verify a proof
make verify PROOF=proof.bin                          # verify a saved proof
```

> Proving is resource-heavy (GPU / large RAM for some backends). Execution
> (`make execute`) is the lightweight path for correctness checks.

### Benchmark

```bash
make bench          # execution-level cycle/step counts per zkVM (mock + real),
                    # emits a machine-readable bench/report.json
```

### Regenerate golden vectors

```bash
cd conformance
cargo run --release -- mock --out-dir vectors --name mock   # synthetic block
cargo run --release -- real --npr np.ssz --chain-config cc.ssz \
      --witness-json ew.json --out-dir vectors --name real  # from real fixtures
```

See `conformance/README.md` for the full generator + runner reference.

### Clean

```bash
make clean          # removes build/
```

zkVM SDK versions are the single source of truth in `ZKVM_VERSIONS`; the
guest is built with unmodified upstream xPack GCC, pinned in the release
workflow, and the release job gates on a bit-reproducible independent rebuild.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. The stateless-execution engine this guest builds on
(`zilkworm`/`zilk_core`, derived from erigontech/silkworm, and the `zvm1`
evmone fork) remains Apache-2.0 by its upstream authors; those terms continue
to apply to that code.
