#!/usr/bin/env bash
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Idempotently apply the OpenVM acceleration patches to the fetched zilkworm
# source tree. Run by FetchContent's PATCH_COMMAND with the zilkworm source
# directory as the single argument (PATCH_COMMAND may re-run on reconfigure,
# so an already-applied patch must be a no-op).
set -euo pipefail
PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${1:?usage: apply-patches.sh <zilkworm-src-dir>}"
cd "$SRC_DIR"

apply_patch() { # <dir> <patch>
    local dir="$1" patch="$2"
    if git -C "$dir" apply --reverse --check "$patch" >/dev/null 2>&1; then
        echo "zilkworm patch already applied: $(basename "$patch")"
    else
        git -C "$dir" apply "$patch"
        echo "zilkworm patch applied: $(basename "$patch")"
    fi
}

# OpenVM ECC/modular acceleration hooks in the zvm1 (evmone) submodule.
apply_patch third_party/evmone "$PATCH_DIR/zvm1-openvm-accel.patch"
