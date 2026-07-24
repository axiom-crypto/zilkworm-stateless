SHELL  = /bin/bash
.SHELLFLAGS = -o pipefail -c

NPROC := $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu)
ROOT  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

.PHONY: all guest_sp1 guest_zisk guest_openvm test test-build clean bench

all: guest_sp1 guest_zisk guest_openvm

# ── SP1 guest (rv64im bare-metal ELF) ────────────────────────────────────────
guest_sp1:
	cmake -S $(ROOT)/zkvm/sp1 -B $(ROOT)/build/sp1 \
		-DCMAKE_TOOLCHAIN_FILE=$(ROOT)/zkvm/sp1/cmake/riscv64im-sp1.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/sp1 -j$(NPROC)

# ── ZisK guest (rv64ima bare-metal ELF) ──────────────────────────────────────
guest_zisk:
	cmake -S $(ROOT)/zkvm/zisk -B $(ROOT)/build/zisk \
		-DCMAKE_TOOLCHAIN_FILE=$(ROOT)/zkvm/zisk/cmake/riscv64ima-zisk.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/zisk -j$(NPROC)

# ── OpenVM guest (rv64im bare-metal ELF) ─────────────────────────────────────
guest_openvm:
	cmake -S $(ROOT)/zkvm/openvm -B $(ROOT)/build/openvm \
		-DCMAKE_TOOLCHAIN_FILE=$(ROOT)/zkvm/openvm/cmake/riscv64im-openvm.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/openvm -j$(NPROC)

# ── Benchmarks: execution-level cycle counts per zkVM ────────────────────────
bench:
	$(ROOT)/bench/run.sh

# ── EEST stateless conformance (native host build) ───────────────────────────
# Runs the exact guest entrypoint natively against EEST stateless fixtures.
# Extract pairs first:  conformance vector-gen eest --fixtures <dir> --out-dir <pairs>
conformance-native:
	cmake -S $(ROOT)/conformance/native -B $(ROOT)/build/conformance \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/conformance -j$(NPROC)

# Usage: make conformance PAIRS=path/to/pairs
conformance: conformance-native
	$(ROOT)/build/conformance/z6m_conformance --pairs $(PAIRS)

# ── EF blockchain test suite (native x86_64) ──────────────────────────────────
test-build:
	cmake -S $(ROOT)/tests -B $(ROOT)/build/tests \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/tests -j$(NPROC)

# Run all BlockchainTests (GeneralStateTests + ValidBlocks + InvalidBlocks)
test: test-build
	$(ROOT)/build/tests/z6m_test \
		$(ROOT)/tests/ethereum-tests/BlockchainTests

# Run a specific sub-directory of tests, e.g.: make test-only SUITE=GeneralStateTests/stExample
test-only: test-build
	$(ROOT)/build/tests/z6m_test \
		$(ROOT)/tests/ethereum-tests/BlockchainTests \
		$(SUITE)

clean:
	rm -rf $(ROOT)/build
