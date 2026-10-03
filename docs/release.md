# Release process

This document is the release control surface for jankurai-tools-proof. It covers
the version source, the changelog, the release automation, integrity and SBOM
evidence, and rollback. Launch gates require every section below to be backed by
a real artifact or command.

## Version source

The single source of truth for the version is the [`VERSION`](../VERSION) file at
the repository root. The crate versions in
`crates/jankurai-proofbind/Cargo.toml` and `crates/jankurai-proofmark/Cargo.toml`
and any release tag MUST stay coherent with `VERSION`. Tags follow the family
pattern `jankurai-tools-proof-v<MAJOR.MINOR.PATCH>-split.<N>` as described in
[`SPLIT.md`](../SPLIT.md).

## Changelog

Every release records its user-visible changes in
[`CHANGELOG.md`](../CHANGELOG.md) under a heading that matches the new `VERSION`.
The `Unreleased` section is promoted to a dated version heading at tag time.

## Reviewed local release path

Jeryu is the source authority. A release candidate advances only through the
local protected lifecycle:

1. Bump [`VERSION`](../VERSION) and promote the `Unreleased` section of
   [`CHANGELOG.md`](../CHANGELOG.md).
2. Run `just check`, `just contract-drift`, the required-mode Proofbind and
   Proofmark fixture, mapped security, and CI doctor on the exact candidate.
3. Push the source branch to the private local Jeryu forge and open a protected
   pull request. A distinct reviewer and the repository-required check must
   approve the exact head before a distinct merger fast-forwards `main`.
4. Create the next unused immutable
   `jankurai-tools-proof-v<version>-split.<N>` tag at the merged commit and read
   it back from Jeryu. Tags never move.
5. Bind the merged commit, tree, source checksum, public-API baseline, SBOM, and
   proof receipts in the release evidence before installation or mirroring.

The public mirror is a later distribution surface, not release authority or
proof. Release builds depend on the protected Jeryu commit and immutable tag,
never on a branch or an unreviewed mirror.

## Changed release evidence

Changed-path attribution and repository-wide readiness are separate evidence
questions. `ops/ci/changed-fast-audit.sh <base>` preserves the exact Git change
in its proof plan, classifies tracked, untracked, renamed, deleted, and
unchanged context/release controls from
`agent/supporting-evidence.json`, and evaluates repository-wide release rules
against the full exact candidate tree. Missing, renamed, deleted, or untracked
required support evidence fails closed; an unchanged support document remains
visible without being mislabeled as changed.

The resulting receipt binds the supporting-evidence classification, proof plan,
and full-tree score by SHA-256. It requires score at least 85, zero caps, and
zero hard findings. It does not lower a threshold, suppress a finding, or turn
prose into runtime qualification.

## Integrity, provenance, and SBOM

- **Dependency integrity**: builds are reproducible because `Cargo.lock` is
  committed and every CI lane uses `--locked`.
- **Public API**: `bash scripts/ci-local.sh contract-drift` regenerates each
  crate's simplified `cargo-public-api` surface with pinned tool and Rust
  versions and rejects any digest that differs from
  `agent/public-api-baseline.json`.
- **SBOM**: the security lane runs Syft over the exact source tree and emits the
  CycloneDX artifact at `target/jankurai/sbom.json`.
- **Provenance**: the security job runs `gitleaks detect`, offline
  `cargo audit --no-fetch`, and Syft; the audit and
  tool-adoption lanes publish exact-head score and proof artifacts.
- **Build hosts**: GitHub is a publishing mirror and runs no workflows. CI runs
  on the forge and our hosts, and releases are built and signed on our servers.
  A separate change introduces key-based release signing.

## Launch gate

The release launch gate is the final checklist that must be green, with
artifact-backed evidence, before any tag is published. No release ships until
every item below has a real proof artifact, not a prose claim:

- **Security**: the `security` job (`gitleaks detect` + `cargo audit`) is green
  and its log is attached.
- **Backups**: this is a library workspace with no datastore, so the backup
  obligation is the committed `Cargo.lock` plus the immutable source tag; any
  consumer-facing data backup is the consumer's launch gate, not this repo's.
- **Monitoring**: the jankurai audit job publishes `repo-score` artifacts that
  are the monitoring signal for score regressions across releases.
- **Rollback**: the rollback procedure below is rehearsed and its last-known-good
  tag is recorded.
- **Abuse and rate limit controls**: the proof crates expose no network surface,
  so rate limit / abuse controls are out of scope here; downstream services that
  embed these crates own that launch-gate item.

A failing launch-gate item blocks the release; it is never waived silently.

## Rollback

If a release regresses:

1. Identify the last known-good tag
   (`jankurai-tools-proof-v<version>-split.<N>`).
2. Re-pin consumers to that immutable commit and tag; tags are never moved or
   deleted.
3. Create an additive revert commit from protected `main`, add a `### Fixed`
   entry describing the rollback, and use the same protected review lifecycle.
4. Re-run `just check`, `just contract-drift`, required proof, security, and CI
   doctor on the rollback candidate before cutting a new immutable tag.

Because tags are immutable and `Cargo.lock` is committed, any prior release can
be rebuilt bit-for-bit from its tag.
