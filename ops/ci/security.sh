#!/usr/bin/env bash
# Security lane: secret scanning plus dependency vulnerability scanning.
# gitleaks scans for committed secrets; cargo audit checks the Rust dependency
# tree. The same lane runs locally via `just security`.
set -euo pipefail
ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

log "security lane: gitleaks + cargo audit + syft SBOM"
gitleaks detect --source . --no-banner --redact
cargo audit
mkdir -p target/jankurai
syft scan dir:. -o cyclonedx-json=target/jankurai/sbom.json
