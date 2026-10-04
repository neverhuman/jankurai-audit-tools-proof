#!/usr/bin/env bash
# Public component proof: controlled hostile fixtures and the complete Rust suite.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

echo "[ci] required lane: ci-local lane contract"
bash scripts/ci-local-lanes-test.sh

mkdir -p target/jankurai
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
bash ops/ci/governed-jankurai-hostile-test.sh
bash ops/ci/changed-fast-evidence-test.sh
bash ops/ci/contract-drift.sh
cargo test --workspace --locked
