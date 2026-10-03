# jankurai-tools-proof Testing

Testing is routed proof. Agents should not guess which tests matter; the
machine-readable route lives in [`agent/test-map.json`](../agent/test-map.json).

| Lane | Purpose |
| --- | --- |
| `fast` | deterministic local proof for most edits (`cargo check` + `cargo nextest run`) |
| `test` | the full workspace test suite for both crates |
| `security` | secret scanning (`gitleaks`) plus dependency review (`cargo audit`) |
| `contract-drift` | regenerate pinned Rust public APIs and compare exact baseline digests |
| `audit` | jankurai repo score and hard-rule findings, written to `.jankurai/repo-score.{json,md}` |
| `check` | release/merge gate: format, lint, fast, security, and self-audit |

## Crate proof suites

- **`jankurai-proofbind`** carries integration tests under
  `crates/jankurai-proofbind/tests/` plus a `proptest` property suite that
  exercises surface classification invariants. The authorization boundary path
  has negative tests that assert a non-owner request is forbidden. Trusted
  `HLT-022-AUTHZ-ISOLATION-GAP` coverage additionally requires a qualified
  producer to observe the relevant execution.
- **`jankurai-proofmark`** carries integration tests under
  `crates/jankurai-proofmark/tests/` that prove obligations move from `review`
  to `pass` only when the matching coverage, mutation, and negative-behavior
  proof receipts are present. Its hostiles retain zero-hit LCOV lines, reject
  legacy hit-only JSON as an executable-universe claim, reject omitted added
  executable lines and empty LCOV intersections, reject absent production
  coverage, and keep test/example source out of the production LCOV denominator.
- **Receipt completeness** requires every lane and receipt kind. File-loaded
  receipts are unverified imports: even a successful typed execution claim,
  exact command, matching rule and repository declaration cannot grant trusted
  execution coverage. Imported reports remain available for diagnosis.
- **Agent-tool rule binding** tests retain command, rule and path checks as
  necessary conditions. Neither repository declarations nor a file receipt
  can authorize its own producer. Legacy strings, duplicate IDs, review
  statuses, wrong rules, unrelated paths and unrelated commands remain invalid.
- **Non-circular lane proof** is required. A script cannot use its own not-yet-
  completed receipt as evidence. Map the implementation path to a lower-level
  focused hostile/contract lane; the outer orchestrator may emit the higher-
  level lane receipt only after that command actually returns successfully.
- **Tool adoption** ratchets the candidate against the fixed protected
  predecessor and runs Proofbind and Proofmark in required mode over the same
  real compiler-covered Git fixture. Zero obligations, unavailable coverage,
  review verdicts, or any missing required receipt make the lane fail.

Run everything with `cargo nextest run --workspace` (lane `fast`/`test`).

## Configuration and incomplete inputs

Proofbind parses TOML before classifying it. Cargo manifests/configuration,
toolchains, lane catalogs and audit policy retain obligations when strengthened,
weakened or emptied. Unknown configuration also retains changed-behavior proof.
Comments and informational strings do not declare executable tools. Only the
explicit informational TOML shape is inert outside known policy roles; JSON
baselines, schemas and ownership maps remain policy inputs.

Shell programs retain process/input and negative-behavior obligations alongside
CI hardening. This routing is conservative: a safe implementation still needs
proof that its boundary works. It does not establish a vulnerability from the
presence of a shell command.

Required changed inputs must be bounded regular UTF-8 files. Missing, malformed,
oversized, symlinked or concurrently changed inputs fail analysis. Malformed
present catalogs fail instead of becoming empty catalogs. Missing Git context
also fails; local discovery includes staged, unstaged and untracked changes.
These file checks do not replace the producer's confined source snapshot.

Run the focused contracts with:

```sh
cargo test -p jankurai-proofbind --test configuration_authority --locked
```

The existing tool-adoption lane uses its pinned older auditor. Its result does
not qualify the new producer boundary. Final family adoption additionally needs
the qualified supervised Core command and a real producer-positive execution.

Public Rust API drift is executable evidence, not a prose declaration.
`bash scripts/ci-local.sh contract-drift` requires `cargo-public-api 0.52.0`,
uses the pinned nightly rustdoc required for rustdoc JSON with Cargo offline,
regenerates all three crate surfaces, and compares exact SHA-256 digests with
the reviewed `agent/public-api-baseline.json`.

Changed-fast release evidence is split deliberately: the proof plan retains the
exact Git change, while repository-wide readiness is evaluated on the full
candidate tree. `ops/ci/changed-fast-evidence-test.sh` covers modified,
untracked, renamed, deleted, and unchanged support documents plus a traversal
hostile. `ops/ci/changed-fast-audit.sh` then rejects missing support, score below
85, any cap, or any hard finding.

## Repair receipts and telemetry

When a proof lane fails, keep the next agent on the shortest possible rerun path.

- Emit structured errors instead of only free-form prose whenever the tool can do it.
- Record the failing command, exit code, changed paths, artifact paths, and the
  rerun command in the receipt.
- Prefer typed telemetry or JSON envelopes under `target/jankurai/` over ad hoc
  log spam.
- Surface the repair hint, docs URL, and common fixes together so the next rerun
  is obvious.

Observability repairs should stay typed. Each crate's proof receipt carries a
typed surface with `purpose`, `reason`, `common fixes`, a `docs_url`, and a
`repair_hint` field so the next rerun stays local instead of forcing a re-read of
chat history. An opaque failure with no `reason` and no `docs_url` is itself a
finding, not a pass.

## Budgets, quotas, and stops

Paid or unbounded work needs an explicit ceiling before it starts. These crates
run no paid APIs, but the proof lanes still declare their bounds:

- State the **budget** in time, runner minutes, or CI dollars for every lane.
- State the **quota** or spend cap that stops the run: the workspace test and
  audit lanes run under a fixed runner timeout on our CI hosts.
- State the **kill switch** / **stop condition**: a non-zero exit from any
  `ops/ci/*.sh` lane is the stop condition that aborts the pipeline, and the
  `spend cap` for an unbounded proof loop is the lane timeout above.
- Capture evidence of the stop in the receipt so the next agent can tell a
  planned stop from a silent failure.

## Agent-friendly exceptions

The default answer is "follow the standard." When a rule must be waived, follow
the dated, owned, expiring exception pattern documented in
[`docs/exceptions.md`](exceptions.md). Every exception records its `purpose`, the
`reason` it exists, the `common fixes` that remove it, and a `docs_url` /
`repair_hint` so the next agent can close it locally.
