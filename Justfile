# jankurai-tools-proof root command surface.
# One-command setup and validation lanes for agents and CI.
# Every lane below is deterministic, hermetic, and runnable from the repo root.

# Default: list available lanes.
default:
    @just --list

# One-command bootstrap: install the toolchain components this repo needs.
setup:
    rustup component add rustfmt clippy
    cargo fetch --locked

# Alias for setup so `just install` and `just bootstrap` also resolve.
install: setup

bootstrap: setup

# Deterministic fast lane: the narrowest proof loop for agent iteration.
fast:
    cargo check --workspace --locked
    cargo nextest run --workspace

test-proofbind:
    cargo nextest run -p jankurai-proofbind

test-proofmark:
    cargo nextest run -p jankurai-proofmark

# Regenerate every public Rust surface with pinned tools and compare the
# reviewed digest baseline.
contract-drift:
    bash scripts/ci-local.sh contract-drift

# Run the full local check: format, lint, fast lane, API drift, security, and audit.
check: fmt lint fast contract-drift security audit

# Verify is an alias of check for agents that look for a `verify` lane.
verify: check

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Run the workspace test suite.
test:
    cargo nextest run --workspace

# Security lane: secret scanning, dependency vulnerability scanning, and SBOM.
# gitleaks scans for committed secrets; cargo audit checks the Rust dependency
# tree; syft emits a CycloneDX SBOM.
security:
    gitleaks detect --source . --no-banner --redact
    cargo audit
    syft scan dir:. -o cyclonedx-json=target/jankurai/sbom.json

# Jankurai self-audit lane: writes the repo-score artifacts that CI uploads.
audit:
    bash ops/ci/governed-jankurai audit . --full --no-score-history --json .jankurai/repo-score.json --md .jankurai/repo-score.md

# Print the declared version.
versions:
    cat VERSION
