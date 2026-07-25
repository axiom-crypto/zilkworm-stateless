#!/usr/bin/env bash
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Idempotently apply the OpenVM acceleration patches to the fetched zilkworm
# source tree. Run by FetchContent's PATCH_COMMAND with the zilkworm source
# directory as the single argument.
#
# PATCH_COMMAND re-runs on reconfigure and the patch itself changes as the
# acceleration work evolves, so every run first restores the files the patch
# touches and then applies it. Deciding "already applied?" by test-applying in
# reverse is not safe here: a tree carrying a *superset* of the current patch
# passes that check and silently keeps the extra hunks, which is how a stale
# revision survives a rebuild. The tree is a FetchContent clone, so there is
# never local work to preserve.
set -euo pipefail
PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${1:?usage: apply-patches.sh <zilkworm-src-dir>}"
cd "$SRC_DIR"

apply_patch() { # <dir> <patch>
    local dir="$1" patch="$2" name files
    name="$(basename "$patch")"

    # --numstat parses the patch, not the tree, so this works from any state.
    files="$(git -C "$dir" apply --numstat "$patch" | cut -f3)"
    # shellcheck disable=SC2086
    git -C "$dir" checkout -- $files
    git -C "$dir" apply "$patch"
    echo "zilkworm patch applied: $name"
}

# OpenVM ECC/pairing acceleration hooks in the zvm1 (evmone) submodule.
apply_patch third_party/evmone "$PATCH_DIR/zvm1-openvm-accel.patch"

# Int256 acceleration for intx::uint256 (EVM 256-bit stack arithmetic).
apply_patch third_party/intx "$PATCH_DIR/intx-openvm-int256.patch"
