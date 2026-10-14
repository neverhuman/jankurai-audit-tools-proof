#!/usr/bin/env bash
# The launcher tests build controlled binaries/receipts under a private TempDir.
# They also prove the root-owned site file is the only source of site paths
# (src/site.rs); ops/ci/governed-site-test.sh proves the same for lib.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
cargo test --locked -p jankurai-governed-launcher --lib
