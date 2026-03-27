#!/usr/bin/env bash
#
# package_precompiled.sh — Build iota_nif and update the 'precompiled' branch
#
# Usage:
#   ./scripts/package_precompiled.sh               # full build + update branch
#   ./scripts/package_precompiled.sh --skip-build   # update branch using existing .so
#
# This script:
#   1. Syncs Cargo.toml version from iota_nif.app.src (single source of truth)
#   2. Builds the Rust NIF in release mode (unless --skip-build)
#   3. Creates/updates an orphan 'precompiled' branch with library files only
#      (Erlang sources, precompiled .so, hook-free rebar.config, mix.exs)
#   4. Tags the branch as v<version>-precompiled
#   5. Creates a tar.gz archive in artifacts/ for optional GitHub Release upload
#
# The precompiled branch can be used directly as a rebar3/Mix git dependency
# — no Rust toolchain required on the consumer side.
#
# No temporary files are left in the working tree — all staging happens in
# /tmp and is cleaned up automatically.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# Extract version from the single source of truth: iota_nif.app.src
VERSION=$(grep '{vsn,' src/iota_nif.app.src | sed 's/.*"\(.*\)".*/\1/')
ARCH="$(uname -m)"
OS="linux"
ARTIFACT_NAME="iota_nif-${VERSION}-${OS}-${ARCH}"
TAG="v${VERSION}-precompiled"

echo "==> Packaging iota_nif v${VERSION} for ${OS}-${ARCH}"

# --- Step 1: Sync Cargo.toml version from iota_nif.app.src ---
CARGO_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
if [[ "$CARGO_VERSION" != "$VERSION" ]]; then
    echo "==> Syncing Cargo.toml version: ${CARGO_VERSION} → ${VERSION}"
    sed -i "s/^version = \"${CARGO_VERSION}\"/version = \"${VERSION}\"/" Cargo.toml
else
    echo "==> Cargo.toml version already in sync (${VERSION})"
fi

# --- Step 2: Build the Rust NIF (unless --skip-build) ---
if [[ "${1:-}" != "--skip-build" ]]; then
    echo "==> Building Rust NIF (release mode)..."
    cargo build --release

    echo "==> Copying NIF binary to priv/"
    mkdir -p priv
    if [[ -f target/release/libiota_nif.so ]]; then
        cp target/release/libiota_nif.so priv/libiota_nif.so
    elif [[ -f target/release/libiota_nif.dylib ]]; then
        cp target/release/libiota_nif.dylib priv/libiota_nif.so
    else
        echo "ERROR: No compiled NIF found in target/release/"
        exit 1
    fi
else
    echo "==> Skipping build (--skip-build)"
    if [[ ! -f priv/libiota_nif.so ]]; then
        echo "ERROR: priv/libiota_nif.so not found. Run without --skip-build first."
        exit 1
    fi
fi

echo "==> NIF binary: $(ls -lh priv/libiota_nif.so | awk '{print $5}')"

# --- Step 3: Stage library files in a temp directory ---
echo "==> Assembling library files..."

STAGING_DIR=$(mktemp -d)
WORKTREE_DIR="/tmp/iota_nif_precompiled_$$"

cleanup() {
    cd "$PROJECT_DIR" 2>/dev/null || true
    git worktree remove "$WORKTREE_DIR" --force 2>/dev/null || true
    rm -rf "$STAGING_DIR" "$WORKTREE_DIR" 2>/dev/null || true
}
trap cleanup EXIT

STAGE="$STAGING_DIR/lib"
mkdir -p "$STAGE"

# Erlang sources (preserving DDD directory structure)
cp -r src "$STAGE/src"
cp -r include "$STAGE/include"
find "$STAGE/src" -name "*.rs" -delete

# Precompiled NIF binary
mkdir -p "$STAGE/priv"
cp priv/libiota_nif.so "$STAGE/priv/"

# Hook-free rebar.config (no cargo build hooks)
cat > "$STAGE/rebar.config" <<'REBAR_EOF'
{erl_opts, [debug_info]}.

%% Include subdirectories for Erlang source files (DDD structure)
{src_dirs, ["src", "src/identity", "src/notarization", "src/credential"]}.

%% Precompiled: no pre/post hooks — NIF binary is already in priv/

{deps, []}.

%% Common Test configuration
{ct_opts, [
    {sys_config, []},
    {logdir, "_build/test/logs"}
]}.

{profiles, [
    {test, [
        {erl_opts, [debug_info, nowarn_export_all]}
    ]}
]}.
REBAR_EOF

# Mix project file for Elixir consumers
[[ -f mix.exs ]] && cp mix.exs "$STAGE/"

# Metadata
cp README.md "$STAGE/" 2>/dev/null || true
cp LICENSE "$STAGE/" 2>/dev/null || true

# --- Step 4: Update the 'precompiled' branch via git worktree ---
echo "==> Updating precompiled branch..."

# Clean up any stale worktree references
git worktree prune 2>/dev/null || true

if git rev-parse --verify precompiled >/dev/null 2>&1; then
    # Branch exists — attach a worktree to it
    git worktree add "$WORKTREE_DIR" precompiled
    # Clear existing content (preserve .git file used by worktree)
    find "$WORKTREE_DIR" -mindepth 1 -maxdepth 1 -not -name '.git' -exec rm -rf {} +
else
    # Create a new orphan branch (no history shared with main)
    git worktree add --orphan -b precompiled "$WORKTREE_DIR" 2>/dev/null || {
        # Fallback for git < 2.41 (no --orphan support for worktree)
        git worktree add --detach "$WORKTREE_DIR"
        git -C "$WORKTREE_DIR" checkout --orphan precompiled
        git -C "$WORKTREE_DIR" rm -rf . 2>/dev/null || true
    }
fi

# Populate worktree with staged library files
cp -r "$STAGE"/* "$WORKTREE_DIR/"

# Commit
git -C "$WORKTREE_DIR" add -A
if git -C "$WORKTREE_DIR" diff --cached --quiet 2>/dev/null; then
    echo "==> No changes to commit (precompiled branch already up to date)"
else
    git -C "$WORKTREE_DIR" commit -m "Precompiled v${VERSION} for ${OS}-${ARCH}"
    echo "==> Committed to precompiled branch"
fi

# Tag (points to the precompiled branch HEAD)
PRECOMPILED_HEAD=$(git -C "$WORKTREE_DIR" rev-parse HEAD)
git tag -f "$TAG" "$PRECOMPILED_HEAD"
echo "==> Tagged ${TAG}"

# --- Step 5: Create tar.gz archive for GitHub Release ---
mkdir -p "$PROJECT_DIR/artifacts"
ARCHIVE_STAGE="$STAGING_DIR/$ARTIFACT_NAME"
mv "$STAGE" "$ARCHIVE_STAGE"
tar -czf "$PROJECT_DIR/artifacts/${ARTIFACT_NAME}.tar.gz" -C "$STAGING_DIR" "$ARTIFACT_NAME"

echo ""
echo "==> Done!"
echo ""
echo "    Precompiled branch:  updated with v${VERSION} for ${OS}-${ARCH}"
echo "    Tag:                 ${TAG}"
echo "    Archive:             artifacts/${ARTIFACT_NAME}.tar.gz"
echo ""
echo "==> To publish:"
echo "    git push origin precompiled --force"
echo "    git push origin ${TAG} --force"
echo ""
echo "    # Optional: upload tar.gz to a GitHub Release"
echo "    gh release create v${VERSION} artifacts/${ARTIFACT_NAME}.tar.gz \\"
echo "      --title 'v${VERSION}' --notes 'Precompiled NIF for ${OS}-${ARCH}'"
echo ""
echo "==> Downstream usage (no Rust toolchain needed):"
echo ""
echo "    # rebar3 (rebar.config):"
echo "    {iota_nif, {git, \"https://github.com/anspn/iota_nif.git\", {tag, \"${TAG}\"}}}"
echo ""
echo "    # Mix (mix.exs):"
echo "    {:iota_nif, git: \"https://github.com/anspn/iota_nif.git\", tag: \"${TAG}\"}"
