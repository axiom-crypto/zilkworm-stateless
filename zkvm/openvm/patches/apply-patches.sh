#!/usr/bin/env bash
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Idempotently apply the OpenVM acceleration patches to the fetched zilkworm
# source tree. Run by FetchContent's PATCH_COMMAND with the zilkworm source
# directory as the single argument.
#
# PATCH_COMMAND re-runs on reconfigure, and the patch itself changes as the
# acceleration work evolves, so this handles three states: pristine tree
# (apply), tree already carrying this exact patch (no-op), and tree carrying
# an older revision of it (restore the touched files, then apply).
set -euo pipefail
PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${1:?usage: apply-patches.sh <zilkworm-src-dir>}"
cd "$SRC_DIR"

apply_patch() { # <dir> <patch>
    local dir="$1" patch="$2" name
    name="$(basename "$patch")"

    if git -C "$dir" apply --reverse --check "$patch" >/dev/null 2>&1; then
        echo "zilkworm patch already applied: $name"
        return
    fi

    if ! git -C "$dir" apply --check "$patch" >/dev/null 2>&1; then
        # A different revision of the patch is applied: restore just the files
        # this patch touches, then apply cleanly. The tree is a FetchContent
        # clone, so there is no user work to preserve.
        echo "zilkworm patch $name does not apply cleanly; restoring touched files"
        local files
        files="$(git -C "$dir" apply --numstat "$patch" | cut -f3)"
        # shellcheck disable=SC2086
        git -C "$dir" checkout -- $files
    fi

    git -C "$dir" apply "$patch"
    echo "zilkworm patch applied: $name"
}

# OpenVM ECC/pairing acceleration hooks in the zvm1 (evmone) submodule.
apply_patch third_party/evmone "$PATCH_DIR/zvm1-openvm-accel.patch"

# Int256 acceleration for intx::uint256 (EVM 256-bit stack arithmetic).
apply_patch third_party/intx "$PATCH_DIR/intx-openvm-int256.patch"
