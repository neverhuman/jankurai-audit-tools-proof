# jankurai-tools-proof

Status: initial split-family extraction
Owner: Jankurai maintainers
Last reviewed: 2026-06-12
Applies to: jankurai-tools-proof

## Role

Proofbind, proofmark, proof receipt helpers, and proof schemas.

## Repositories

- Historical Jeryu repo: `root/jankurai-tools-proof`
- GitHub publishing mirror: `neverhuman/jankurai-tools-proof`
- Release tag pattern: `jankurai-tools-proof-v1.7.0-split.0`
- Source extraction commit: `cea83b0cbe204be276a2f0299cd760f6812ea2b0`

## Split Rules

- The forge is authoritative; GitHub is a publishing mirror and runs no CI.
- Builds, CI and scoring run on the forge and our hosts; releases are built and
  signed on our servers from immutable tags, not branches.
- Local development uses the hub `scripts/fuse.sh` output under `.fusion/`.
- Committed manifests must not depend on sibling checkout paths.
- Generated outputs are regenerated from their source contracts or build commands.

## Required Local Check

```bash
bash scripts/ci-local.sh required
```
