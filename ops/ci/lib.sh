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
# Cargo, fusion, or fallback copy, and nothing here reads one. Release identity
# (auditor version, receipt digest, the toolchain that builds the launcher and
# its exact version strings) is pinned below. Site locations (installation
# root, Cargo/rustup homes) come only from the root-owned file the launcher
# itself trusts, crates/jankurai-governed-launcher/src/site.rs, never from the
# environment: the PR gate runs lanes under `env -i`, and an environment
# variable is exactly what a hostile caller controls.
readonly GOVERNED_JANKURAI_VERSION="jankurai 1.6.11"
readonly GOVERNED_JANKURAI_RECEIPT_SHA256="4b66c7b3d2ce4102b2302a7e73533cdbc2ae48ac02ec76cb6b1ff395ddc91d6a"
readonly GOVERNED_SITE_CONFIG="/etc/jankurai/governed-launcher.json"
readonly GOVERNED_SITE_SCHEMA="jankurai.governed-site/v1"
readonly GOVERNED_JANKURAI_LAUNCHER="$REPO_ROOT/target/debug/jankurai-governed-launcher"
readonly GOVERNED_RUST_TOOLCHAIN="1.95.0-x86_64-unknown-linux-gnu"
readonly GOVERNED_RUSTC_VERSION="rustc 1.95.0 (59807616e 2026-04-14)"
readonly GOVERNED_CARGO_VERSION="cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
# Resolved by resolve_governed_site; reset here so no inherited value survives.
GOVERNED_JANKURAI_ROOT=""
GOVERNED_JANKURAI_BIN=""
GOVERNED_CARGO_HOME=""
GOVERNED_RUSTUP_HOME=""
GOVERNED_CARGO=""
GOVERNED_RUSTC=""
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

# governed_path_is_normalised <path> -- absolute, no empty/./.. components,
# no trailing slash, no ':' or control bytes.
governed_path_is_normalised() {
  local path="$1" component
  local -a components
  [[ "$path" == /* && "$path" != *:* && "$path" != *[[:cntrl:]]* ]] || return 1
  [[ "$path" == / ]] && return 0
  [[ "$path" != */ ]] || return 1
  IFS=/ read -r -a components <<<"${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
  done
}

# governed_chain_ok <anchor> <dir> <owner-uid> <forbidden-mode-bits> -- every
# directory from <anchor> down to <dir> is physical, owned by root or
# <owner-uid>, and has none of <forbidden-mode-bits> (octal) set.
governed_chain_ok() {
  local anchor="$1" dir="$2" owner="$3" forbidden="$4" current relative component uid mode
  governed_path_is_normalised "$anchor" && governed_path_is_normalised "$dir" || return 1
  if [[ "$anchor" == / ]]; then
    relative="${dir#/}"
  elif [[ "$dir" == "$anchor" ]]; then
    relative=""
  elif [[ "$dir" == "$anchor"/* ]]; then
    relative="${dir#"$anchor"/}"
  else
    return 1
  fi
  current="$anchor"
  while :; do
    [[ -d "$current" && ! -L "$current" ]] || return 1
    read -r uid mode < <(/usr/bin/stat -c '%u %a' -- "$current") || return 1
    [[ "$uid" == 0 || "$uid" == "$owner" ]] || return 1
    (( (8#$mode & 8#$forbidden) == 0 )) || return 1
    [[ -n "$relative" ]] || return 0
    component="${relative%%/*}"
    [[ "$relative" == */* ]] && relative="${relative#*/}" || relative=""
    [[ "$current" == / ]] && current="/$component" || current="$current/$component"
  done
}

# resolve_governed_site <config> <config-owner-uid> <anchor> -- read the site
# file the launcher trusts and resolve the pinned toolchain inside its rustup
# home. Production passes only the constants (load_governed_site); the
# arguments exist so ops/ci/governed-site-test.sh can prove the checks.
resolve_governed_site() {
  local config="$1" config_owner="$2" anchor="$3" uid mode links root toolchain_bin self
  self="$(/usr/bin/id -u)"
  if [[ ! -e "$config" && ! -L "$config" ]]; then
    printf '[ci] governed site configuration %s is unavailable\n' "$config" >&2
    return 1
  fi
  if ! governed_chain_ok "$anchor" "${config%/*}" "$config_owner" 022; then
    printf '[ci] governed site configuration directory is not root-controlled\n' >&2
    return 1
  fi
  if [[ ! -f "$config" || -L "$config" ]]; then
    printf '[ci] governed site configuration %s is unavailable\n' "$config" >&2
    return 1
  fi
  read -r uid mode links < <(/usr/bin/stat -c '%u %a %h' -- "$config") || return 1
  if [[ "$uid" != "$config_owner" ]] || (( (8#$mode & 8#022) != 0 )) || [[ "$links" != 1 ]]; then
    printf '[ci] governed site configuration has an unsafe owner, mode or link count\n' >&2
    return 1
  fi
  if ! /usr/bin/jq -e --arg schema "$GOVERNED_SITE_SCHEMA" '
      (keys == ["cargo_home","extra_path","manifest_repo","root","rustup_home","schema","source_remote"])
      and .schema == $schema
      and (.root | type == "string") and (.cargo_home | type == "string")
      and (.rustup_home | type == "string")' "$config" >/dev/null; then
    printf '[ci] governed site configuration does not match %s\n' "$GOVERNED_SITE_SCHEMA" >&2
    return 1
  fi
  root="$(/usr/bin/jq -r .root "$config")"
  GOVERNED_CARGO_HOME="$(/usr/bin/jq -r .cargo_home "$config")"
  GOVERNED_RUSTUP_HOME="$(/usr/bin/jq -r .rustup_home "$config")"
  toolchain_bin="$GOVERNED_RUSTUP_HOME/toolchains/$GOVERNED_RUST_TOOLCHAIN/bin"
  if ! governed_path_is_normalised "$root" \
    || ! governed_chain_ok "$anchor" "$GOVERNED_CARGO_HOME" "$self" 002 \
    || ! governed_chain_ok "$anchor" "$toolchain_bin" "$self" 002; then
    printf '[ci] governed site directories are not trusted\n' >&2
    return 1
  fi
  GOVERNED_JANKURAI_ROOT="$root"
  GOVERNED_JANKURAI_BIN="$root/bin/jankurai"
  GOVERNED_CARGO="$toolchain_bin/cargo"
  GOVERNED_RUSTC="$toolchain_bin/rustc"
  if [[ ! -x "$GOVERNED_CARGO" || -L "$GOVERNED_CARGO" || ! -x "$GOVERNED_RUSTC" || -L "$GOVERNED_RUSTC" ]]; then
    printf '[ci] governed Rust toolchain is unavailable\n' >&2
    return 1
  fi
  if [[ "$(/usr/bin/env -i PATH=/usr/bin:/bin RUSTUP_HOME="$GOVERNED_RUSTUP_HOME" "$GOVERNED_RUSTC" --version)" != "$GOVERNED_RUSTC_VERSION" \
    || "$(/usr/bin/env -i PATH=/usr/bin:/bin RUSTUP_HOME="$GOVERNED_RUSTUP_HOME" CARGO_HOME="$GOVERNED_CARGO_HOME" "$GOVERNED_CARGO" --version)" != "$GOVERNED_CARGO_VERSION" ]]; then
    printf '[ci] governed Rust toolchain version mismatch\n' >&2
    return 1
  fi
}

load_governed_site() {
  resolve_governed_site "$GOVERNED_SITE_CONFIG" 0 /
}

# Build the reviewed Rust launcher with the pinned toolchain from the trusted
# site file. The launcher performs every binary/receipt check in-process and
# executes a sealed memfd.
build_governed_jankurai_launcher() {
  load_governed_site || return 1
  /usr/bin/env -i \
    CARGO_HOME="$GOVERNED_CARGO_HOME" \
    CARGO_NET_OFFLINE=true \
    CARGO_TARGET_DIR="$REPO_ROOT/target" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    HOME=/nonexistent \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/bin:/bin \
    RUSTC="$GOVERNED_RUSTC" \
    RUSTUP_HOME="$GOVERNED_RUSTUP_HOME" \
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
