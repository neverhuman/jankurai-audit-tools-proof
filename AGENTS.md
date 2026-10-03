# jankurai-tools-proof Agent Instructions

Read `SPLIT.md` first. This repository is one member of the Jankurai split family.

- GitHub publishing mirror: `neverhuman/jankurai-tools-proof`. It runs no CI;
  builds, CI and scoring run on the forge and our hosts.
- Do not add committed cross-repo `path = "../..."` dependencies. Use the hub fusion workspace for local path patches.
- Do not hand-edit generated artifacts listed in `agent/generated-zones.toml`.
- Run `bash scripts/ci-local.sh required` before handing off changes.
