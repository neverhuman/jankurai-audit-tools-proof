#!/usr/bin/env bash
# Shared CI helper module sourced by every ops/ci/<lane>.sh script.
# Single source of truth for tool version pins and artifact assertions so
# local runs and the CI hosts execute the exact same commands.
set -euo pipefail

if [[ "${JANKURAI_TOOLS_CI_LIB_LOADED:-0}" == "1" ]]; then
  return 0
fi
readonly JANKURAI_TOOLS_CI_LIB_LOADED=1

# Resolve the repository root regardless of where a lane is invoked from.
ci_lib_source="${BASH_SOURCE[0]}"
ci_lib_dir="${ci_lib_source%/*}"
[[ "$ci_lib_dir" != "$ci_lib_source" ]] || ci_lib_dir=.
REPO_ROOT="$(cd "$ci_lib_dir/../.." && pwd -P)"
export REPO_ROOT

# Pinned tool versions. Lanes read these so CI and local environments match.
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.97.1}"
export GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.18.4}"
export CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.21.0}"
export NEXTEST_VERSION="${NEXTEST_VERSION:-0.9}"
readonly CARGO_PUBLIC_API_BIN="$(command -v cargo-public-api)"
readonly CARGO_PUBLIC_API_VERSION="cargo-public-api 0.52.0"

# Governed Jankurai identity. Callers must never select an ambient PATH,
# Cargo, fusion, or fallback copy.
readonly GOVERNED_JANKURAI_BIN="/home/ubuntu/.jeryu/bin/jankurai"
readonly GOVERNED_JANKURAI_VERSION="jankurai 1.6.11"
readonly GOVERNED_JANKURAI_RECEIPT="/home/ubuntu/.jeryu/receipts/jankurai/sha256/4b66c7b3d2ce4102b2302a7e73533cdbc2ae48ac02ec76cb6b1ff395ddc91d6a.json"
readonly GOVERNED_JANKURAI_RECEIPT_SHA256="4b66c7b3d2ce4102b2302a7e73533cdbc2ae48ac02ec76cb6b1ff395ddc91d6a"
readonly GOVERNED_JANKURAI_LAUNCHER="$REPO_ROOT/target/debug/jankurai-governed-launcher"
readonly GOVERNED_RUST_TOOLCHAIN_ROOT="/home/ubuntu/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu"
readonly GOVERNED_CARGO="$GOVERNED_RUST_TOOLCHAIN_ROOT/bin/cargo"
readonly GOVERNED_RUSTC="$GOVERNED_RUST_TOOLCHAIN_ROOT/bin/rustc"
export JANKURAI_NO_UPDATE_CHECK=1
export GIT_TERMINAL_PROMPT=0

# log <message> -- emit a structured progress line.
log() {
  printf '[ci] %s\n' "$*"
}

# require_tool <binary> -- fail fast with an actionable message when a pinned
# tool is missing from PATH so local parity gaps surface before the lane runs.
require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$tool" >&2
    return 1
  fi
}

# Build the reviewed Rust launcher with fixed toolchain paths. The launcher
# performs every binary/receipt check in-process and executes a sealed memfd.
build_governed_jankurai_launcher() {
  if [[ ! -x "$GOVERNED_CARGO" || -L "$GOVERNED_CARGO" || ! -x "$GOVERNED_RUSTC" || -L "$GOVERNED_RUSTC" ]]; then
    printf '[ci] governed Rust toolchain is unavailable\n' >&2
    return 1
  fi
  /usr/bin/env -i \
    CARGO_HOME=/home/ubuntu/.cargo \
    CARGO_NET_OFFLINE=true \
    CARGO_TARGET_DIR="$REPO_ROOT/target" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    HOME=/nonexistent \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/bin:/bin \
    RUSTC="$GOVERNED_RUSTC" \
    RUSTUP_HOME=/home/ubuntu/.rustup \
    TZ=UTC \
    "$GOVERNED_CARGO" build --locked --offline \
    -p jankurai-governed-launcher --bin jankurai-governed-launcher
}

require_governed_jankurai() {
  local actual_version
  if [[ ! -f "$GOVERNED_JANKURAI_LAUNCHER" || -L "$GOVERNED_JANKURAI_LAUNCHER" || ! -x "$GOVERNED_JANKURAI_LAUNCHER" ]]; then
    printf '[ci] governed Rust launcher is unavailable; build it first\n' >&2
    return 1
  fi
  actual_version="$("$GOVERNED_JANKURAI_LAUNCHER" --version 2>/dev/null || true)"
  if [[ "$actual_version" != "$GOVERNED_JANKURAI_VERSION" ]]; then
    printf '[ci] governed Jankurai version mismatch\n' >&2
    return 1
  fi
}

run_governed_jankurai() {
  build_governed_jankurai_launcher || return 1
  require_governed_jankurai || return 1
  "$GOVERNED_JANKURAI_LAUNCHER" "$@"
}

# assert_artifact <path> -- confirm a lane produced the artifact it promised.
assert_artifact() {
  local artifact="$1"
  if [ ! -e "$REPO_ROOT/$artifact" ]; then
    printf '[ci] expected artifact missing: %s\n' "$artifact" >&2
    return 1
  fi
  log "artifact present: $artifact"
}

source "$REPO_ROOT/ops/ci/public-auditor.sh"
