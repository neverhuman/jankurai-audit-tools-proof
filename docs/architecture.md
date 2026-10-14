# jankurai-tools-proof Architecture

This repository is a single-purpose Rust workspace holding the Jankurai proof
tooling crates extracted from the main auditor:

```text
crates/jankurai-proofbind   semantic surface routing + proof obligation binding
crates/jankurai-proofmark   changed-behavior proof receipt engine
crates/jankurai-governed-launcher
                             installed-auditor identity and execution boundary
schemas/                    JSON Schemas for the proof artifacts both crates emit
```

New implementation is Rust-first. There is no web, PostgreSQL, or Python AI/data
surface committed in this repo, so those arms of the family standard do not
apply here. Effects (filesystem, environment, time, networking) stay in the
library entrypoints; the pure routing and receipt logic is deterministic.

## Crate roles

- **`jankurai-proofbind`** classifies changed paths into semantic surfaces
  (public API, authz boundary, input boundary, agent-tool supply) and binds each
  surface to the proof obligations and required receipt kinds it must satisfy.
  Every declared lane and receipt kind is conjunctive. Changed test and example
  sources require a successful typed `test_execution` receipt on the declared
  lane whose `command` exactly matches the test-map/proof-lane command.
  Non-Rust fallback surfaces use that same declared-command binding rather than
  an impossible Rust Proofmark requirement. A lane may not satisfy an
  obligation by claiming an exact obligation ID or by reporting `command=true`.
  Agent-tool surfaces route to their exact test-map/proof-lane command. The
  reviewed lane declaration and the emitted receipt must both bind every
  required rule; missing, duplicate, malformed, partial, wrong-path, or
  self-asserted rule coverage remains unsatisfied.
- **`jankurai-proofmark`** ingests obligations plus coverage, mutation, and
  negative-proof evidence and writes a proof receipt that marks each obligation
  as `pass`, `review`, or `missing`. The fixed Git change and candidate source
  define potentially executable changed lines; LCOV `DA` entries then prove
  which of those lines are coverable and hit. An executable changed line absent
  from LCOV is uncovered, so partial or empty intersections cannot pass.
  Declarations and structural-only Rust lines remain outside the executable
  denominator. Legacy JSON that reports hits without `coverable_lines` has no
  trusted executable universe and remains `review`/`block`.
- **`jankurai-governed-launcher`** opens the installed auditor and installation
  receipt through descriptor-held, no-follow filesystem custody, validates
  owner, mode, link count, bounded size, exact SHA-256, and receipt fields,
  seals an exact memfd copy, and executes it with a fixed minimal environment.
  Caller-selected `PATH`, Cargo, Git, home, wrapper, and diff configuration
  cannot replace the governed executable or its build/runtime authority.
  Release identity (binary and receipt SHA-256, source commit/tag/tree, build
  toolchain) is compiled in. Site locations are not, and they are never read
  from the caller's environment: the launcher reads one root-owned file,
  `/etc/jankurai/governed-launcher.json` (schema `jankurai.governed-site/v1`:
  `root`, `cargo_home`, `rustup_home`, `extra_path`, `source_remote`,
  `manifest_repo`, nothing else). The file must be a regular single-link file
  owned by root with no group/world write, in directories only root controls.
  Every directory it names must be a physical directory owned by root or the
  effective user with no world-writable component on its way from `/`. The
  sealed `PATH` is `/usr/bin:/bin` followed by `extra_path`, and the receipt
  must name both forge URLs exactly. `ops/ci/lib.sh` reads the same file to find
  the rustup home and builds the launcher only with the pinned
  `1.95.0-x86_64-unknown-linux-gnu` toolchain inside it, after checking its
  exact `rustc`/`cargo` version strings. A host without the file refuses the
  governed lane instead of falling back to defaults.

## Local workspace ownership

| Path | Role |
| --- | --- |
| `crates/` | proofbind, proofmark, and governed-launcher Rust crates |
| `schemas/` | JSON Schemas for proof plans, witnesses, obligations, and receipts |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI and fusion helpers |

Agents should prefer `agent/owner-map.json` and `agent/test-map.json` for
changes, then route to the smallest proof lane.
