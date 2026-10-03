# jankurai-tools-proof

<!-- jankurai-badge:start -->
[![Jankurai score: 91/100](agent/jankurai-badge.svg)](agent/jankurai-badge.json)
<!-- jankurai-badge:end -->

[![jankurai audit](https://img.shields.io/badge/jankurai--audit-pass-green.svg)](docs/testing.md)

Rust source for the **Jankurai** proof tooling crates: `jankurai-proofbind`
(semantic surface routing and proof obligation binding), `jankurai-proofmark`
(changed-behavior proof receipt engine), and `jankurai-governed-launcher`
(content-authenticated execution of the installed auditor). This repository is
one member of the Jankurai split family; read [`SPLIT.md`](SPLIT.md) for the
family contract and [`AGENTS.md`](AGENTS.md) for agent routing rules.

## Stack

This member is a Rust-only workspace. It has no web, database, queue, or Python
product surface. See [`docs/architecture.md`](docs/architecture.md).

## Quick start

```bash
# One-command setup (toolchain + locked dependencies).
just setup

# Deterministic fast lane (check + tests).
just fast

# Full local check: format, lint, fast, security, and self-audit.
just check
```

The full command surface lives in the root [`Justfile`](Justfile). Continuous
integration runs the same lanes on the forge and our own hosts. GitHub is a
publishing mirror only; it runs no workflows. Releases are built and signed on
our servers.

## Layout

| Path | Role |
| --- | --- |
| `crates/jankurai-proofbind` | semantic surface routing + obligation binding |
| `crates/jankurai-proofmark` | changed-behavior proof receipt engine |
| `crates/jankurai-governed-launcher` | authenticated installed-auditor launcher |
| `schemas/` | JSON Schemas for the proof artifacts |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI and fusion helpers |

## Documentation

- [Architecture](docs/architecture.md)
- [Testing](docs/testing.md)
- [Boundaries](docs/boundaries.md)
- [Release process](docs/release.md)
- [Agent exceptions and overrides](docs/exceptions.md)

## Agent handoff

Agents must read [`AGENTS.md`](AGENTS.md) and [`SPLIT.md`](SPLIT.md) before
changing source. The required lane validates the repository-wide context and
release controls declared in
[`agent/supporting-evidence.json`](agent/supporting-evidence.json). Changed
audits keep the exact Git path attribution in their proof plan while evaluating
repository-wide release rules against the full candidate tree; see
[`ops/ci/changed-fast-audit.sh`](ops/ci/changed-fast-audit.sh).

## Versioning

The current version is recorded in [`VERSION`](VERSION) and the change history in
[`CHANGELOG.md`](CHANGELOG.md). The local Jeryu review, proof, immutable-tag,
integrity, and rollback gates are documented in
[`docs/release.md`](docs/release.md).

## License

See [`LICENSE`](LICENSE).
