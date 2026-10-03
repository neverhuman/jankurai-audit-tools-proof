#!/usr/bin/env bash
# CI doctor: confirms the local environment has every tool the ops/ci lanes
# depend on, with the versions pinned in ops/ci/lib.sh. Run this before pushing
# to verify your machine matches what the CI hosts provide.
set -euo pipefail
script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../ops/ci/lib.sh"

log "ci-doctor: checking required tools"

status=0
for tool in cargo rustc cargo-nextest gitleaks cargo-audit cargo-public-api; do
  if command -v "$tool" >/dev/null 2>&1; then
    log "ok: $tool ($(command -v "$tool"))"
  else
    printf '[ci] MISSING: %s\n' "$tool" >&2
    status=1
  fi
done

if build_governed_jankurai_launcher && require_governed_jankurai; then
  log "ok: $GOVERNED_JANKURAI_VERSION ($GOVERNED_JANKURAI_BIN; receipt sha256:$GOVERNED_JANKURAI_RECEIPT_SHA256)"
else
  status=1
fi

if [[ ! -x "$CARGO_PUBLIC_API_BIN" || -L "$CARGO_PUBLIC_API_BIN" ]]; then
  printf '[ci] governed cargo-public-api binary is unavailable\n' >&2
  status=1
elif [[ "$("$CARGO_PUBLIC_API_BIN" --version)" != "$CARGO_PUBLIC_API_VERSION" ]]; then
  printf '[ci] governed cargo-public-api version mismatch\n' >&2
  status=1
else
  log "ok: $CARGO_PUBLIC_API_VERSION ($CARGO_PUBLIC_API_BIN)"
fi

log "pinned versions: rust=$RUST_TOOLCHAIN gitleaks=$GITLEAKS_VERSION cargo-audit=$CARGO_AUDIT_VERSION nextest=$NEXTEST_VERSION cargo-public-api=$CARGO_PUBLIC_API_VERSION jankurai=$GOVERNED_JANKURAI_VERSION"

if [ "$status" -ne 0 ]; then
  printf '[ci] environment does not match CI; install the tools above\n' >&2
fi
exit "$status"
